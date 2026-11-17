// ============================================================================
// linoh C-API 实现 — v0.5 (crypto) + v1.0 (Connection/Endpoint/Stream)
// ============================================================================
#include "linoh/linoh_c.h"
#include "linoh/linoh_tensorstream.h"
#include "linoh/base/key.hpp"
#include "linoh/control_plane.hpp"
#include "linoh/multimodal/channel.hpp"
#include "linoh/multimodal/ep_session.hpp"
#include "linoh/multimodal/tensor_stream.hpp"  // v5.1.0 T-LA: Tensor 分片流水线 C-API
#include "linoh/tls/crypto_provider.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/logging.hpp"
#include "linoh/util/bytes.hpp"
#include "linoh/util/key_file.hpp"   // v4.5.0: 密钥文件持久化
#include "linoh/endpoint/connection.hpp"
#include "linoh/protocol/path_strategy.hpp"  // 【多模态隧道】PathSelectionStrategy + create_strategy_by_name
#include "linoh/protocol/packet.hpp"
#include "linoh/protocol/application_message.hpp"  // v3.2.0 Direct Return Path
#include "linoh/protocol/session_id.hpp"     // V3.5 P5-B: SessionId C-API
#include "linoh/protocol/compression.hpp"
#include "linoh/fec/fec_adaptive.hpp"    // V3.5 P5-B: Compression C-API
#include "linoh/nat/relay_pool.hpp"          // V3-B: RelayPool 跨域骨干 Relay
#include "linoh/relay/ws_client.hpp"         // 【硬件规定】linoh relay WebSocket 编解码（纯字节，不依赖 asio）
#include "linoh/relay/stride.hpp"            // 【硬件规定】linoh relay STRIDE 帧编解码（纯字节，不依赖 asio）
#include "linoh/relay/auth.hpp"              // 【硬件规定】linoh relay 认证握手（ServerChallenge / ClientAuth / sign_challenge）
#include "linoh/net/mtu.hpp"                  // V3-B: MtuNegotiator::negotiate_cross_domain
#include "linoh/protocol/bbr_v2.hpp"          // V3-B: BbrV2Controller 跨域参数
#include "linoh/protocol/congestion_controller.hpp"  // V3-B: CongestionController
#include "linoh/event/event_loop.hpp"           // v4.3.0 M7: 事件循环 select!
#include "linoh/event/shutdown_event.hpp"       // v4.3.0 M7: ShutdownEvent
#include "linoh/event/timer_event.hpp"          // v4.3.0 M7: TimerEvent
#include "linoh/event/linoh_event_source.hpp"   // v4.3.0 M7: LinohEventSource

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
// POSIX 上没有 SOCKET 类型，用 int 替代 Windows 的 SOCKET 句柄
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
// Windows closesocket ↔ POSIX close
static inline int closesocket(int fd) { return ::close(fd); }
#endif

#include <cstring>
#include <cstdio>
#include <algorithm>
#include <exception>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>

using namespace linoh;

// ============================================================================
// A5: C-API 异常守卫宏
//
// extern "C" 函数内 C++ 异常穿越语言边界是 UB（多数实现 std::terminate）。
// 统一捕获异常转为安全返回值，避免宿主进程崩溃。
//
// 用法：
//   linoh_error_t f() {
//       LINOH_C_GUARD_BEGIN                    // try {
//       ... 原函数体（含 return）...
//       LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)  // } catch(...) { ...; return rv; }
//   }
//
// 函数体中间的 return 直接跳出 try 块正常返回；catch 仅兜底。
// 注意：不覆盖函数内独立线程 lambda 的异常（需在线程内单独捕获）。
// ============================================================================
#define LINOH_C_GUARD_BEGIN  try {
#define LINOH_C_GUARD_END(rv) \
    } catch (const std::exception &e) { \
        set_error((std::string("linoh_c: exception: ") + e.what()).c_str()); \
        return (rv); \
    } catch (...) { \
        set_error("linoh_c: unknown exception"); \
        return (rv); \
    }

// v4.3.0 M7: void 返回函数的异常守卫（return ; 对 void 合法）
#define LINOH_C_GUARD_END_VOID() \
    } catch (const std::exception &e) { \
        set_error((std::string("linoh_c: exception: ") + e.what()).c_str()); \
        return; \
    } catch (...) { \
        set_error("linoh_c: unknown exception"); \
        return; \
    }

extern "C" {

// A5: 前向声明，供异常守卫宏在 set_error 定义（见后文）之前使用
static void set_error(const char *msg);

// ============================================================================
// v0.5: Crypto primitives
// ============================================================================

const char *linoh_version(void) {
    // v2.0.0 (2026-07-31): 全国消费级显卡聚合算力网基础架构（Phase 1 完成）
    //   - BBR v2 拥塞控制 + RelayPool 多维选择（geo+load+uplink）
    //   - NodeProfile 四维节点画像 + 多路径协同拥塞控制（加权 round-robin）
    // v5.4.0 (2026-10-04): 借鉴 ScaleFabric 的 P0+P1+P2 全量落地
    //   F7 指标导出（connection/endpoint 统计 + 消息直方图 + 路径占比）
    //   F6 连接级路径热切换（三态 override + 双通道故障检测）
    //   F4 credit 预约流控（BLOCKED 声明即保障 + write_ex/reserve 阻塞语义）
    //   F3' 异步发送原语（flush_async，非阻塞提交）
    static const char v[] = "5.4.0";
    return v;
}

linoh_error_t linoh_generate_keypair(linoh_secret_key_t *sk,
                                     linoh_public_key_t *pk) {
    LINOH_C_GUARD_BEGIN  // A5: 异常守卫
    if (!sk || !pk) return LINOH_ERR_PARAM;
    auto native_sk = base::SecretKey::generate();
    auto native_pk = native_sk.public_key();
    auto sk_span = native_sk.as_span();
    std::memcpy(sk->bytes, sk_span.data(), std::min<size_t>(sk_span.size(), LINOH_KEY_SIZE));
    auto pk_span = native_pk.as_span();
    std::memcpy(pk->bytes, pk_span.data(), std::min<size_t>(pk_span.size(), LINOH_KEY_SIZE));
    LINOH_INFO("linoh_c: keypair generated");
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_secret_key_from_bytes(const uint8_t *data, size_t len,
                                          linoh_secret_key_t *out) {
    if (!data || !out) return LINOH_ERR_PARAM;
    if (len < LINOH_KEY_SIZE) return LINOH_ERR_PARAM;
    std::memcpy(out->bytes, data, LINOH_KEY_SIZE);
    return LINOH_OK;
}

// v4.5.0: 从私钥派生公钥（Ed25519 曲线运算）
linoh_error_t linoh_derive_public_key(const linoh_secret_key_t *sk,
                                       linoh_public_key_t *out_pk) {
    LINOH_C_GUARD_BEGIN
    if (!sk || !out_pk) return LINOH_ERR_PARAM;
    auto native_sk = base::SecretKey::from_bytes(
        std::span<const uint8_t>(sk->bytes, LINOH_KEY_SIZE));
    auto native_pk = native_sk.public_key();
    auto pk_span = native_pk.as_span();
    std::memcpy(out_pk->bytes, pk_span.data(), LINOH_KEY_SIZE);
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

// v4.5.0: 从 32 字节原始字节构造公钥
linoh_error_t linoh_public_key_from_bytes(const uint8_t *data, size_t len,
                                           linoh_public_key_t *out) {
    if (!data || !out) return LINOH_ERR_PARAM;
    if (len < LINOH_KEY_SIZE) return LINOH_ERR_PARAM;
    std::memcpy(out->bytes, data, LINOH_KEY_SIZE);
    return LINOH_OK;
}

// v4.5.0: 持久化私钥到文件（委托 linoh::util::save_key_file）
linoh_error_t linoh_save_key_file(const char *path,
                                   const linoh_secret_key_t *sk) {
    LINOH_C_GUARD_BEGIN
    if (!path || !sk) return LINOH_ERR_PARAM;
    auto native_sk = base::SecretKey::from_bytes(
        std::span<const uint8_t>(sk->bytes, LINOH_KEY_SIZE));
    if (native_sk.is_zero()) return LINOH_ERR_PARAM;
    if (!util::save_key_file(path, native_sk)) {
        return LINOH_ERR_INTERNAL;
    }
    LINOH_INFO("linoh_c: key file saved");
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

// v4.5.0: 从文件加载私钥（委托 linoh::util::load_key_file）
linoh_error_t linoh_load_key_file(const char *path,
                                   linoh_secret_key_t *out_sk) {
    LINOH_C_GUARD_BEGIN
    if (!path || !out_sk) return LINOH_ERR_PARAM;
    base::SecretKey native_sk;
    if (!util::load_key_file(path, native_sk)) {
        return LINOH_ERR_CRYPTO;
    }
    auto sk_span = native_sk.as_span();
    std::memcpy(out_sk->bytes, sk_span.data(), LINOH_KEY_SIZE);
    LINOH_INFO("linoh_c: key file loaded");
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

// v4.5.0: 加载或生成密钥文件（委托 linoh::util::load_or_generate_key_file）
linoh_error_t linoh_load_or_generate_key_file(const char *path,
                                               linoh_secret_key_t *out_sk,
                                               linoh_public_key_t *out_pk) {
    LINOH_C_GUARD_BEGIN
    if (!path || !out_sk || !out_pk) return LINOH_ERR_PARAM;
    auto result = util::load_or_generate_key_file(path);
    if (!result.ok) {
        return LINOH_ERR_INTERNAL;
    }
    auto sk_span = result.sk.as_span();
    std::memcpy(out_sk->bytes, sk_span.data(), LINOH_KEY_SIZE);
    auto pk_span = result.pk.as_span();
    std::memcpy(out_pk->bytes, pk_span.data(), LINOH_KEY_SIZE);
    LINOH_INFO("linoh_c: load_or_generate_key_file ok");
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

size_t linoh_public_key_fmt_short(const linoh_public_key_t *pk,
                                  char *buf, size_t buf_size) {
    LINOH_C_GUARD_BEGIN  // A5: 异常守卫
    if (!pk || !buf || buf_size < 16) return 0;
    base::PublicKey native;
    uint8_t bytes[LINOH_KEY_SIZE];
    std::memcpy(bytes, pk->bytes, LINOH_KEY_SIZE);
    native = base::PublicKey::from_bytes(std::span<const uint8_t>(bytes, LINOH_KEY_SIZE));
    std::string s = native.fmt_short();
    size_t n = std::min<size_t>(s.size(), buf_size - 1);
    std::memcpy(buf, s.data(), n);
    buf[n] = '\0';
    return n;
    LINOH_C_GUARD_END(0)
}

linoh_error_t linoh_random_bytes(uint8_t *out, size_t len) {
    LINOH_C_GUARD_BEGIN  // A5: 异常守卫
    if (!out) return LINOH_ERR_PARAM;
    if (linoh::crypto::crypto_random_bytes(std::span<uint8_t>(out, len))) return LINOH_OK;
    return LINOH_ERR_INTERNAL;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_hmac_sha256(const uint8_t *key, size_t key_len,
                                const uint8_t *msg, size_t msg_len,
                                linoh_hmac_t *out) {
    LINOH_C_GUARD_BEGIN  // A5: 异常守卫
    if (!key || !msg || !out) return LINOH_ERR_PARAM;
    auto result = crypto::HMAC_SHA256::compute(
        std::span<const uint8_t>(key, key_len),
        std::span<const uint8_t>(msg, msg_len));
    std::memcpy(out->bytes, result.data(), 32);
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

size_t linoh_aead_seal(const linoh_aead_key_t *key,
                       const uint8_t nonce[LINOH_AEAD_NONCE_SIZE],
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *plaintext, size_t plaintext_len,
                       uint8_t *out, size_t out_size) {
    LINOH_C_GUARD_BEGIN  // A5: 异常守卫
    if (!key || !nonce || !plaintext || !out) return 0;
    if (out_size < plaintext_len + LINOH_AEAD_TAG_SIZE) return 0;
    auto aead = tls::global_provider().default_aead();
    if (aead->nonce_size() < LINOH_AEAD_NONCE_SIZE) return 0;
    std::size_t written = aead->seal(
        std::span<const uint8_t>(key->bytes, LINOH_AEAD_KEY_SIZE),
        std::span<const uint8_t>(nonce, LINOH_AEAD_NONCE_SIZE),
        std::span<const uint8_t>(ad, ad_len),
        std::span<const uint8_t>(plaintext, plaintext_len),
        std::span<uint8_t>(out, out_size));
    return written;
    LINOH_C_GUARD_END(0)
}

size_t linoh_aead_open(const linoh_aead_key_t *key,
                       const uint8_t nonce[LINOH_AEAD_NONCE_SIZE],
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *cipher_with_tag, size_t ct_len,
                       uint8_t *out, size_t out_size) {
    LINOH_C_GUARD_BEGIN  // A5: 异常守卫
    if (!key || !nonce || !cipher_with_tag || !out) return 0;
    if (ct_len < LINOH_AEAD_TAG_SIZE) return 0;
    auto aead = tls::global_provider().default_aead();
    std::size_t written = aead->open(
        std::span<const uint8_t>(key->bytes, LINOH_AEAD_KEY_SIZE),
        std::span<const uint8_t>(nonce, LINOH_AEAD_NONCE_SIZE),
        std::span<const uint8_t>(ad, ad_len),
        std::span<const uint8_t>(cipher_with_tag, ct_len),
        std::span<uint8_t>(out, out_size));
    return written;
    LINOH_C_GUARD_END(0)
}

void linoh_ticket_to_bytes(const linoh_session_ticket_t *ticket,
                           uint8_t out[LINOH_TICKET_SIZE]) {
    if (!ticket || !out) return;
    std::memcpy(out + LINOH_TICKET_PEER_ID_OFFSET, ticket->peer_id.bytes, LINOH_KEY_SIZE);
    std::memcpy(out + LINOH_TICKET_MASTER_SECRET_OFFSET, ticket->master_secret, LINOH_KEY_SIZE);
    uint32_t med = ticket->max_early_data_bytes;
    out[LINOH_TICKET_MAX_EARLY_OFFSET + 0] = static_cast<uint8_t>((med >> 24) & 0xFF);
    out[LINOH_TICKET_MAX_EARLY_OFFSET + 1] = static_cast<uint8_t>((med >> 16) & 0xFF);
    out[LINOH_TICKET_MAX_EARLY_OFFSET + 2] = static_cast<uint8_t>((med >> 8) & 0xFF);
    out[LINOH_TICKET_MAX_EARLY_OFFSET + 3] = static_cast<uint8_t>(med & 0xFF);
}

void linoh_ticket_from_bytes(const uint8_t data[LINOH_TICKET_SIZE],
                             linoh_session_ticket_t *out) {
    if (!data || !out) return;
    std::memcpy(out->peer_id.bytes, data + LINOH_TICKET_PEER_ID_OFFSET, LINOH_KEY_SIZE);
    std::memcpy(out->master_secret, data + LINOH_TICKET_MASTER_SECRET_OFFSET, LINOH_KEY_SIZE);
    uint32_t med = (static_cast<uint32_t>(data[LINOH_TICKET_MAX_EARLY_OFFSET + 0]) << 24) |
                   (static_cast<uint32_t>(data[LINOH_TICKET_MAX_EARLY_OFFSET + 1]) << 16) |
                   (static_cast<uint32_t>(data[LINOH_TICKET_MAX_EARLY_OFFSET + 2]) << 8) |
                   (static_cast<uint32_t>(data[LINOH_TICKET_MAX_EARLY_OFFSET + 3]));
    out->max_early_data_bytes = med;
}

linoh_error_t linoh_derive_zero_rtt(const uint8_t master_secret[LINOH_KEY_SIZE],
                                    linoh_aead_key_t *out) {
    if (!master_secret || !out) return LINOH_ERR_PARAM;
    const char *label = "zero-rtt";
    std::vector<uint8_t> msg;
    for (int i = 0; label[i]; ++i) msg.push_back(static_cast<uint8_t>(label[i]));
    auto hmac = crypto::HMAC_SHA256::compute(
        std::span<const uint8_t>(master_secret, LINOH_KEY_SIZE),
        std::span<const uint8_t>(msg.data(), msg.size()));
    std::memcpy(out->bytes, hmac.data(), LINOH_AEAD_KEY_SIZE);
    return LINOH_OK;
}

// ============================================================================
// v1.0: Opaque handle wrappers
// ============================================================================

// 本地 callback 类型定义（避免命名空间解析歧义）
namespace {
using c_on_conn_fn   = void(*)(linoh_connection_t*, void*);
using c_on_stream_fn = void(*)(linoh_stream_t*, void*);
using c_on_state_fn  = void(*)(linoh_connection_t*, int, void*);
using c_on_close_fn  = void(*)(linoh_connection_t*, void*);
}

struct linoh_connection;

struct linoh_stream {
    linoh_connection *parent{nullptr};   // 反向指向连接（用于 flush）
    std::shared_ptr<endpoint::Connection> conn;
    std::shared_ptr<endpoint::Stream> stream;
    // v1.5.0.3: F3 OOS 回调 payload（堆上分配，stream free 时统一释放）
    void *oos_payload{nullptr};
};

struct linoh_connection {
    SOCKET sock{INVALID_SOCKET};
    std::shared_ptr<endpoint::Connection> conn;
    struct sockaddr_in peer_addr{};
    std::vector<uint8_t> recv_buf;
    std::vector<uint8_t> send_buf;
    std::mutex send_mu;
    std::atomic<bool> closed{false};
    // 反向指针，用于 linoh_connection_free 时从 endpoint->conns 中安全移除
    struct linoh_endpoint *endpoint{nullptr};
    // P4 fix(2026-07-20): 保存 conn 在 endpoint->conns 中的 key，
    // free 时直接 erase(key) 替代 O(N) 遍历查找。
    std::vector<uint8_t> conn_key;
    bool has_conn_key{false};
    // ep-M4 (v1.7.0.8): peer_addr(sin_addr 4B + sin_port 2B) 打包成 uint64_t key，
    // 用于 endpoint->addr_to_conn_key_ 反向映射。free 时据此 O(1) 删除反向映射。
    // 根因：dcid 查找失败时回退 O(n) find_if 全表扫描，高并发下性能瓶颈。
    std::uint64_t addr_key{0};
    bool has_addr_key{false};
    // 上一次通知给上层的状态（用于状态变化检测）
    // 修复（2026-07-17）：之前 on_state_cb 从未被调用，导致 worker 永远等不到 ESTABLISHED
    // 注意：recv_thread 单线程访问，无需 atomic
    endpoint::ConnState last_notified_state{endpoint::ConnState::Initial};
    // v1.5 P1-2: 引用计数（避免 self_ref UAF：调用方持有 conn 期间 ep 被 free 后 conn 被 UAF）
    // 初始 1（由 ep->conns map 持有）。retain/release 增减，归零不释放（仍由 map 持有）。
    std::atomic<int> refcount{1};
    // ep-P5 (v1.7.0.8): pending 数据标志，避免 endpoint_poll 遍历全部 conn flush
    //   linoh_stream_write / handshake flight 产生时置 true，flush 排空后置 false。
    //   endpoint_poll 仅 flush has_pending_data=true 的 conn，减少无效锁竞争。
    std::atomic<bool> has_pending_data{false};
    // v5.4 F3'（借鉴 ScaleFabric 算-传紧耦合）：异步 flush 状态
    std::atomic<bool> async_flush_on{false};   // 异步 flush 循环开关
    std::thread async_flush_thread;             // 每连接惰性启动（首次 flush_async）
    // v3.8.0 biased select!: close 事件已通知标记，避免重复调用 on_close_cb。
    //   poll 线程检测到 ConnState::Closed/Draining 时置 true 并触发 on_close_cb。
    //   与 last_notified_state 独立（后者驱动 on_state_cb，本字段驱动 on_close_cb）。
    bool close_notified{false};

    // ---- v5.4 F6（借鉴 ScaleFabric <1ms 故障收敛）：连接级路径热切换 ----
    // 现状：sendto 目标由 endpoint 级 relay_active 全局布尔决定（K-PYRO-015 语义）。
    // F6：每连接独立故障判定——连续发送失败（Linux: sendto ECONNREFUSED；
    // Windows: recvfrom WSAECONNRESET 10054 → endpoint 信号 → 巡检联动）达阈值
    // 即翻转本连接发送目标（三态 override：-1 跟随全局 / 0 强制 direct / 1 强制 relay），
    // 计数导出（F7）。静默丢包（无 ICMP）场景仍由 v5.3.1 idle 巡检兜底判死。
    int8_t   path_override{-1};        // 发送目标覆盖（默认跟随 endpoint 全局）
    uint32_t send_fail_streak{0};      // 连续失败计数（任一成功清零）
    uint32_t reset_streak{0};          // recvfrom-reset 归属计数（独立——Windows 上
                                       // sendto 对死目标常返回成功，不能被其清零）
    uint64_t path_switch_count{0};     // 累计切换次数（F7 导出）
    double   last_send_ms{0.0};        // 最近发送时刻（reset 信号归属判定）
    static constexpr uint32_t kPathSwitchThreshold = 3;     // sendto 失败路径
    static constexpr uint32_t kResetSwitchThreshold = 1;    // reset 归属路径（v5.5 F6.2：
    // 2→1 压缩切换时延。Windows UDP ICMP 一次性上报——下一错误要等 recvfrom
    // 消费后才再报，信号天然稀疏，2 次阈值实测 2287ms。误伤面评估：归属条件
    // 已排除活连接（最近 2s 有收包），单信号翻转仅影响发送目标选择且
    // relay 不可用时保持 direct（fail-safe），健康连接偶发信号不改行为）
};

// 前向声明（notify_state_if_changed 完整实现在 map_state 之后）
static void notify_state_if_changed(struct linoh_endpoint *ep, linoh_connection_t *lc);

struct linoh_endpoint {
    SOCKET sock{INVALID_SOCKET};
    uint16_t local_port{0};
    uint16_t local_preferred_mtu{1280};  // K-LINOH-PERF-001: MTU 协商用
    // K-LINOH-READBLK-001 (v5.3.1): 连接活性巡检参数（create 时从 config 归一化，
    // 0 = 关闭机制；默认 idle 30s / keepalive 10s）。仅 recv_thread 读写。
    uint32_t idle_timeout_ms{30000};
    uint32_t keepalive_ms{10000};
    // v5.5 F6.2: ACK 空窗路径切换阈值（0=关闭；create 时从 config 归一化）
    uint32_t path_ack_timeout_ms{0};
    std::atomic<double> last_ack_seen_ms{0.0};   // 最近 ACK 到达时刻（steady，handle_ack_frame 更新）
    // K-LINOH-READBLK-001 (v5.3.1): read_ex 等待的通知通道。
    // 唤醒源：①数据到达（recv_thread dispatch 后）②巡检 tick（≤500ms 粒度，
    // 兼作连接死亡事件的兜底唤醒）③read_ex 自身超时。
    std::mutex io_cv_mu;
    std::condition_variable io_cv;
    // v5.4 F6: 最近一次 recvfrom WSAECONNRESET(10054)/ECONNREFUSED 时刻
    //（Windows 上 ICMP 不可达报在 recvfrom 而非 sendto；巡检消费此信号）
    std::atomic<double> last_udp_reset_ms{0.0};
    std::atomic<bool> running{false};
    std::thread recv_thread;
    std::mutex mu;
    std::map<std::vector<uint8_t>, std::shared_ptr<linoh_connection>> conns;
    // ep-M4 (v1.7.0.8): peer_addr → conn_key 反向映射，O(1) 查找替代 O(n) find_if。
    // 根因：recv_thread 在 dcid 查找失败时回退 find_if 全表扫描 conns，
    //       连接数多时（N 个 worker）每包 O(N)，高并发下成为瓶颈。
    // 修复：维护 addr(sin_addr+sin_port) → conn_key 的 unordered_map，
    //       查找路径变为 O(1) hash + O(log N) conns.find(key)。
    // 同步规则：conns 插入/删除时必须同步插入/删除 addr_to_conn_key_（均在 ep->mu 下）。
    std::unordered_map<std::uint64_t, std::vector<uint8_t>> addr_to_conn_key_;
    std::queue<linoh_connection_t*> accept_q;
    std::vector<uint8_t> recv_buf;
    std::vector<uint8_t> send_buf;

    // v1.5.0.2.4: draining 队列 — linoh_connection_free 移出 conns 后，
    // 并不立即析构 linoh_connection_t（会触发 endpoint::Connection 析构），
    // 而是 push 到 draining，由 linoh_endpoint_free 在 join recv_thread
    // 之后统一清理。这样 recv_thread 中 in-flight 的 `auto lc = it->second`
    // 局部 shared_ptr 仍能维持 linoh_connection_t 存活，handle_packet
    // 完成后 lc 析构是安全的。
    std::mutex draining_mu;
    std::vector<std::shared_ptr<linoh_connection>> draining;

    // v3.2.0 Direct Return Path: return stream 连接池
    // key = (master_host, master_port)，value = shared_ptr<linoh_connection>
    // 同一 MASTER 多次推理复用 pp-llm/1 连接，减少 dial/握手开销。
    // linoh_endpoint_free 时随 ep 析构统一释放（shared_ptr 引用计数归零）。
    std::mutex return_pool_mu;
    std::map<std::pair<std::string, uint16_t>, std::shared_ptr<linoh_connection>> return_pool;

    // v3.2.1 P1: MASTER 端 return slot 管理（轻量，与 C++ DirectReturnManager 平行）
    // 直连路径（入站 pp-llm/1 ResultPP[DirectReturn] 拦截）与逐跳路径（inject）竞争同一 slot。
    struct CReturnSlot {
        std::uint64_t req_id{0};
        std::uint32_t token{0};
        std::vector<std::uint8_t> result;  // 结果 payload
        bool ready{false};                  // 任一路径已写入结果
        bool cancelled{false};
        // P3-1: 分片重组缓冲
        std::uint16_t total_shards{0};
        std::uint16_t received_shards{0};
        std::vector<std::vector<std::uint8_t>> shard_chunks;
    };
    std::mutex return_slots_mu;
    std::condition_variable return_slots_cv;
    std::unordered_map<std::uint32_t, std::unique_ptr<CReturnSlot>> c_return_slots;
    std::unordered_map<std::uint64_t, std::uint32_t> c_req_id_to_token;
    bool direct_return_inbound_enabled{false};

    // v3.2.1 P1: Direct Return 统计（MASTER + 末节点端合计）
    struct CDirectReturnStats {
        std::uint64_t return_streams_opened{0};
        std::uint64_t return_streams_failed{0};
        std::uint64_t results_sent_direct{0};
        std::uint64_t results_received{0};
        std::uint64_t direct_return_won{0};
        std::uint64_t hop_by_hop_won{0};
        std::uint64_t fallback_invoked{0};
        std::uint64_t return_slots_registered{0};
        std::uint64_t return_slots_cancelled{0};
        std::uint64_t pool_hits{0};
        std::uint64_t pool_misses{0};
    };
    CDirectReturnStats dr_stats;
    std::mutex dr_stats_mu;

    c_on_conn_fn   on_conn_cb{nullptr};
    c_on_stream_fn on_stream_cb{nullptr};
    c_on_state_fn  on_state_cb{nullptr};
    c_on_close_fn  on_close_cb{nullptr};
    // P5-C-1: 用 atomic<void*> 替代裸 void*，使 set_user_data 可在任意线程安全调用，
    // 回调在 recv_thread 中 load() 读取，无需显式加锁。
    std::atomic<void*> user_data{nullptr};

    // v1.6.0.1 EP: endpoint 级默认回调（linoh_ep_channel_create 时快照继承）
    // 用 mu_ 保护 set / create 读取的并发（set 一般在启动阶段，create 也在启动阶段，
    // 但保守加锁避免后续运行时 set 与 channel create 竞争）
    linoh_ep_on_dispatch_fn      ep_on_dispatch{nullptr};
    void                        *ep_dispatch_ud{nullptr};
    linoh_ep_on_combine_fn       ep_on_combine{nullptr};
    void                        *ep_combine_ud{nullptr};
    linoh_ep_on_sync_fn          ep_on_sync{nullptr};
    void                        *ep_sync_ud{nullptr};
    linoh_ep_on_frame_dropped_fn ep_on_dropped{nullptr};
    void                        *ep_dropped_ud{nullptr};

    base::SecretKey secret_key;
    std::string alpn;

    // 【硬件规定】linoh 原生 relay 字段 — NAT 穿透使用 linoh relay server，禁止外部隧道
    // 设计：relay client 作为本地 UDP 代理，对 endpoint 核心逻辑透明
    //   1. relay TCP 线程收到对端数据 → 通过 relay_proxy_sock 注入到 endpoint->sock
    //   2. endpoint 发送数据到 127.0.0.1:relay_proxy_port → relay_send_thread 读取 → relay TCP 发送
    //   3. linoh_endpoint_connect 时，若 relay_active，连接到 127.0.0.1:relay_proxy_port
    // 不依赖 asio — 使用裸 TCP socket + ws_client.hpp + stride.hpp 实现 relay 协议
    SOCKET relay_tcp_sock{INVALID_SOCKET};   // TCP 连接到 relay server
    std::thread relay_recv_thread;           // 从 relay server 接收 WebSocket 帧
    std::thread relay_send_thread;           // 从 relay_proxy_sock 读取并转发给 relay server
    std::thread relay_ping_thread;           // Ping 保活线程（每 15s 发送一次 Ping）
    SOCKET relay_proxy_sock{INVALID_SOCKET}; // 本地 UDP 代理 socket，接收 endpoint 发出的数据
    uint16_t relay_proxy_port{0};            // relay_proxy_sock 绑定的本地端口
    base::EndpointId relay_peer_id;          // 目标节点的 EndpointId
    mutable std::mutex relay_peer_id_mu;     // 保护 relay_peer_id 的并发读写（v4.8.1 新增）
    std::atomic<bool> relay_active{false};   // relay 是否已激活
    std::atomic<bool> relay_running{false};  // relay 线程是否运行中
    std::atomic<int64_t> last_pong_ms{0};    // [FIX 2026-08-14] 上次收到 Pong 的时间戳，用于检测半开连接
    std::mutex relay_send_mu;                // 保护 relay_tcp_sock 的发送
    std::vector<uint8_t> relay_leftover;     // HTTP 升级后预读的剩余字节（可能含 ServerChallenge）

    // 【多模态隧道】path_strategy: 路径选择策略（v4.8.0 新增）
    //   - linoh_endpoint_create 时根据 config->path_strategy_name 创建
    //   - 出站连接创建时注入到 Connection::Config，启用策略后 PathMigrationManager 按策略选路
    //   - 为 nullptr 时使用 Connection 默认行为（RttBasedStrategy）
    std::shared_ptr<protocol::PathSelectionStrategy> path_strategy;
};

// P1 前向声明：入站 Direct Return stream 拦截（完整定义见后文 MASTER 端 C-API 段）
// 在 on_stream 回调中优先调用，命中 ResultPP[DirectReturn] 则路由到 return slot
static bool c_try_handle_direct_return_stream(linoh_endpoint_t *ep,
                                               std::shared_ptr<endpoint::Stream> s);

// ============================================================================
// 辅助：错误信息
// ============================================================================

static thread_local char g_error_buf[256] = {0};

const char *linoh_error_str(void) {
    return g_error_buf;
}

static void set_error(const char *msg) {
    std::strncpy(g_error_buf, msg, sizeof(g_error_buf) - 1);
    g_error_buf[sizeof(g_error_buf) - 1] = '\0';
}

// Thread-safe replacement for inet_ntoa (which uses a static internal buffer)
static std::string inet_ntop_safe(struct in_addr addr) {
    char buf[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return std::string(buf);
    }
    return "?";
}

// ep-M4 (v1.7.0.8): 计算 peer_addr 的 uint64_t key（sin_addr 4B + sin_port 2B）。
// 用于 addr_to_conn_key_ 反向映射，替代 O(n) find_if 全表扫描。
// 注：sin_addr/sin_port 均为网络字节序，直接打包保证同一对端地址 key 一致。
static std::uint64_t compute_addr_key(const struct sockaddr_in &addr) {
    std::uint64_t key = 0;
    // 高 32 位放 sin_addr，低 16 位放 sin_port（中间 16 位为 0）
    key = (static_cast<std::uint64_t>(addr.sin_addr.s_addr) << 16)
          | (static_cast<std::uint64_t>(addr.sin_port) & 0xFFFF);
    return key;
}

// ============================================================================
// Stream API
// ============================================================================

const linoh_connection_t *linoh_stream_connection(const linoh_stream_t *s) {
    if (!s) return nullptr;
    return reinterpret_cast<const linoh_connection_t*>(s->parent);
}

uint64_t linoh_stream_id(const linoh_stream_t *s) {
    if (!s || !s->stream) return 0;
    return s->stream->id();
}

int linoh_stream_has_readable(const linoh_stream_t *s) {
    if (!s || !s->stream) return 0;
    // 修复（2026-07-17）：必须获取 stream_mu_ 锁，与 handle_1rtt_packet 互斥
    // 否则并发访问 recv_ vector 会导致数据损坏
    // P1-P3 fix(2026-07-20): 用 readable_size() 替代 recv_buffer().size()，
    // 后者包含已消费但未前移的字节，会误报可读。
    std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
    return s->stream->readable_size() > 0 ? 1 : 0;
}

size_t linoh_stream_read(linoh_stream_t *s, uint8_t *buf, size_t buf_size) {
    LINOH_C_GUARD_BEGIN  // A5: 异常守卫
    if (!s || !s->stream || !buf || buf_size == 0) return 0;
    // 修复（2026-07-17）：必须获取 stream_mu_ 锁，与 handle_1rtt_packet 互斥
    // 否则并发 erase recv_ vector 会导致数据损坏（"unexpected frame type: 0x00" 根因）
    // P1-P3 fix(2026-07-20): 改用 readable_data() + consume() 替代
    // recv_buffer().erase()，避免 O(n) 头部删除。
    std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
    std::size_t avail = s->stream->readable_size();
    if (avail == 0) return 0;
    std::size_t n = std::min<size_t>(buf_size, avail);
    std::memcpy(buf, s->stream->readable_data(), n);
    s->stream->consume(n);
    s->conn->record_msg_received(n);   // v5.4 F7: 消息级画像（应用消费）
    return n;
    LINOH_C_GUARD_END(0)
}

// K-LINOH-READBLK-001 (v5.3.1): 状态判定（数据优先于死亡——残留可读数据允许排空）
static linoh_read_status_t readblk_status(const linoh_stream_t *s) {
    if (s->stream->readable_size() > 0) return LINOH_READ_OK;
    if (s->stream->conn_dead())         return LINOH_READ_CONN_DEAD;
    if (s->stream->fin_received())      return LINOH_READ_FIN;
    // 流未死未 FIN，但连接层已 Closed/Draining → 同样判死（防 FIN 丢失场景）
    if (!s->conn || s->conn->is_closed()) return LINOH_READ_CONN_DEAD;
    return LINOH_READ_EMPTY;
}

size_t linoh_stream_read_ex(linoh_stream_t *s, uint8_t *buf, size_t buf_size,
                            uint32_t timeout_ms, linoh_read_status_t *st) {
    LINOH_C_GUARD_BEGIN
    if (st) *st = LINOH_READ_INVALID;
    if (!s || !s->stream || !buf || buf_size == 0) return 0;

    // 快路径：已有数据 / 已死 / 已 FIN → 直接返回，不进等待
    linoh_read_status_t cur;
    {
        std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
        cur = readblk_status(s);
        if (cur == LINOH_READ_OK) {
            std::size_t avail = s->stream->readable_size();
            std::size_t n = std::min<size_t>(buf_size, avail);
            std::memcpy(buf, s->stream->readable_data(), n);
            s->stream->consume(n);
            s->conn->record_msg_received(n);   // v5.4 F7
            if (st) *st = LINOH_READ_OK;
            return n;
        }
        if (cur != LINOH_READ_EMPTY) { if (st) *st = cur; return 0; }
    }

    if (timeout_ms == 0) { if (st) *st = LINOH_READ_EMPTY; return 0; }

    // 慢路径：等待通知（数据到达 / 巡检 tick / 超时）。ep 从 parent->endpoint 取，
    // 无 endpoint 句柄（理论不可能，防御）时退化为纯超时轮询。
    struct linoh_endpoint *ep = s->parent ? s->parent->endpoint : nullptr;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    for (;;) {
        if (!ep) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        } else {
            std::unique_lock<std::mutex> lk(ep->io_cv_mu);
            // (std::min) 括号形式规避 windows.h min 宏（MSVC）
            ep->io_cv.wait_until(lk, (std::min)(deadline,
                std::chrono::steady_clock::now() + std::chrono::milliseconds(100)));
        }
        {
            std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
            cur = readblk_status(s);
            if (cur == LINOH_READ_OK) {
                std::size_t avail = s->stream->readable_size();
                std::size_t n = std::min<size_t>(buf_size, avail);
                std::memcpy(buf, s->stream->readable_data(), n);
                s->stream->consume(n);
                s->conn->record_msg_received(n);   // v5.4 F7
                if (st) *st = LINOH_READ_OK;
                return n;
            }
            if (cur != LINOH_READ_EMPTY) { if (st) *st = cur; return 0; }
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            if (st) *st = LINOH_READ_EMPTY;
            return 0;
        }
    }
    LINOH_C_GUARD_END(0)
}

int linoh_stream_is_dead(const linoh_stream_t *s) {
    LINOH_C_GUARD_BEGIN
    if (!s || !s->stream) return 1;
    return (s->stream->conn_dead() || !s->conn || s->conn->is_closed()) ? 1 : 0;
    LINOH_C_GUARD_END(1)
}

// ================= v5.4 F7（借鉴 ScaleFabric 可观测方法论）：指标导出 =================
static linoh_conn_state_t map_state(endpoint::ConnState s);   // 前向声明（定义在下方）
static void fill_conn_stats(const linoh_connection_t *c, linoh_connection_stats_t *out) {
    auto cs = c->conn->stats();   // 值拷贝快照（尽力而为）
    out->packets_sent        = cs.packets_sent;
    out->packets_received    = cs.packets_received;
    out->bytes_sent          = cs.bytes_sent;
    out->bytes_received      = cs.bytes_received;
    out->lost_packets        = cs.lost_packets;
    out->retransmitted_packets = cs.retransmitted_packets;
    out->rtt_ema_ms          = cs.rtt_ema_ms;
    out->rttvar_ms           = cs.rttvar_ms;
    out->rto_ms              = cs.rto_ms;
    out->bandwidth_bps       = cs.bandwidth_bps;
    out->pacing_rate_bps     = cs.pacing_rate_bps;
    out->cwnd_bytes          = cs.cwnd_bytes;
    out->msgs_sent           = cs.msgs_sent;
    out->msgs_received       = cs.msgs_received;
    for (int i = 0; i < LINOH_MSG_BUCKETS; ++i) {
        out->msg_size_sent_buckets[i] = cs.msg_size_sent_buckets[i];
        out->msg_size_recv_buckets[i] = cs.msg_size_recv_buckets[i];
    }
    out->pkts_via_direct     = cs.pkts_via_direct;
    out->pkts_via_relay      = cs.pkts_via_relay;
    out->conn_state          = (int) map_state(c->conn->state());
    out->streams_open        = (uint32_t) c->conn->open_stream_count();
    out->idle_timeout_ms     = c->conn->idle_timeout_cfg_ms();
    out->keepalive_ms        = c->conn->keepalive_cfg_ms();
    out->last_activity_age_ms = c->conn->last_activity_age_ms();
    out->path_switch_count = c->path_switch_count;
    out->active_path       = c->path_override;
}

int linoh_connection_get_stats(const linoh_connection_t *c,
                               linoh_connection_stats_t *out) {
    LINOH_C_GUARD_BEGIN
    if (!c || !c->conn || !out) return 0;
    memset(out, 0, sizeof(*out));
    fill_conn_stats(c, out);
    return 1;
    LINOH_C_GUARD_END(0)
}

int linoh_endpoint_get_stats(linoh_endpoint_t *ep,
                             linoh_endpoint_stats_t *out) {
    LINOH_C_GUARD_BEGIN
    if (!ep || !out) return 0;
    memset(out, 0, sizeof(*out));

    std::vector<std::shared_ptr<linoh_connection>> snapshot;
    {
        std::lock_guard<std::mutex> lk(ep->mu);
        snapshot.reserve(ep->conns.size());
        for (auto & kv : ep->conns) snapshot.push_back(kv.second);
    }

    for (auto & lc : snapshot) {
        if (!lc || !lc->conn) continue;
        linoh_connection_stats_t cs{};
        fill_conn_stats(lc.get(), &cs);
        out->conns_total++;
        if (cs.conn_state == LINOH_CONN_ESTABLISHED) out->conns_established++;
        out->packets_sent        += cs.packets_sent;
        out->packets_received    += cs.packets_received;
        out->bytes_sent          += cs.bytes_sent;
        out->bytes_received      += cs.bytes_received;
        out->lost_packets        += cs.lost_packets;
        out->retransmitted_packets += cs.retransmitted_packets;
        if (cs.rtt_ema_ms > out->rtt_ema_ms_max) out->rtt_ema_ms_max = cs.rtt_ema_ms;
        out->msgs_sent           += cs.msgs_sent;
        out->msgs_received       += cs.msgs_received;
        for (int i = 0; i < LINOH_MSG_BUCKETS; ++i) {
            out->msg_size_sent_buckets[i] += cs.msg_size_sent_buckets[i];
            out->msg_size_recv_buckets[i] += cs.msg_size_recv_buckets[i];
        }
        out->pkts_via_direct     += cs.pkts_via_direct;
        out->pkts_via_relay      += cs.pkts_via_relay;
    }
    return 1;
    LINOH_C_GUARD_END(0)
}

size_t linoh_stream_write(linoh_stream_t *s, const uint8_t *data, size_t data_len) {
    LINOH_C_GUARD_BEGIN  // A5: 异常守卫
    if (!s || !s->stream || !data || data_len == 0) return 0;

    // 修复（2026-07-17）：必须获取 stream_mu_ 锁，与 build_1rtt_packet 互斥
    // 否则并发修改 send_ vector（insert vs erase）会导致数据损坏
    std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
    s->stream->write(std::span<const uint8_t>(data, data_len));
    // v5.4 F7: 消息级画像（应用写入次数字节数）
    s->conn->record_msg_sent(data_len);
    // ep-P5 (v1.7.0.8): 标记 connection 有 pending 数据，供 endpoint_poll 快速跳过空 conn
    if (s->parent) {
        s->parent->has_pending_data.store(true, std::memory_order_release);
    }
    return data_len;
    LINOH_C_GUARD_END(0)
}

// ---- v5.4 F4（借鉴 ScaleFabric credit 预约式无损流控）----
// 当前流可再入队量：remote 窗口 - (已发 offset + 待发积压)
static uint64_t f4_stream_capacity(const linoh_stream_t *s) {
    std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
    const std::uint64_t in_flight =
        s->stream->send_offset() + s->stream->send_readable_size();
    return s->conn->stream_send_capacity(s->stream->id(), in_flight);
}

size_t linoh_stream_write_ex(linoh_stream_t *s, const uint8_t *data,
                             size_t data_len, uint32_t timeout_ms) {
    LINOH_C_GUARD_BEGIN
    if (!s || !s->stream || !data || data_len == 0) return 0;

    // 快路径：窗口足够直接写（与 linoh_stream_write 行为一致）
    if (f4_stream_capacity(s) >= data_len) {
        return linoh_stream_write(s, data, data_len);
    }

    // 慢路径：声明需求（BLOCKED 携带期望终点 offset）→ 对端保障回窗 → 等待
    struct linoh_endpoint *ep = s->parent ? s->parent->endpoint : nullptr;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms ? timeout_ms : 1);
    for (;;) {
        {
            std::uint64_t need_offset;
            {
                std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
                need_offset = s->stream->send_offset() +
                              s->stream->send_readable_size() + data_len;
            }
            s->conn->send_stream_data_blocked(s->stream->id(), need_offset);
        }
        if (s->parent) linoh_connection_flush(s->parent);
        if (f4_stream_capacity(s) >= data_len) {
            return linoh_stream_write(s, data, data_len);
        }
        if (std::chrono::steady_clock::now() >= deadline) return 0;
        // 等 MAX_STREAM_DATA 到达（dispatch 后 io_cv 通知；无 ep 时退化为轮询）
        if (ep) {
            std::unique_lock<std::mutex> lk(ep->io_cv_mu);
            ep->io_cv.wait_for(lk, std::chrono::milliseconds(50));
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    LINOH_C_GUARD_END(0)
}

uint64_t linoh_stream_request_reserve(linoh_stream_t *stream,
                                      uint64_t reserve_bytes, uint32_t timeout_ms) {
    LINOH_C_GUARD_BEGIN
    if (!stream || !stream->stream || reserve_bytes == 0) return 0;

    struct linoh_endpoint *ep = stream->parent ? stream->parent->endpoint : nullptr;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms ? timeout_ms : 1);
    for (;;) {
        {
            std::uint64_t need_offset;
            {
                std::lock_guard<std::mutex> lk(stream->conn->stream_mutex());
                need_offset = stream->stream->send_offset() +
                              stream->stream->send_readable_size() + reserve_bytes;
            }
            stream->conn->send_stream_data_blocked(stream->stream->id(), need_offset);
        }
        if (stream->parent) linoh_connection_flush(stream->parent);
        uint64_t cap = f4_stream_capacity(stream);
        if (cap >= reserve_bytes) return cap;
        if (std::chrono::steady_clock::now() >= deadline) return 0;
        if (ep) {
            std::unique_lock<std::mutex> lk(ep->io_cv_mu);
            ep->io_cv.wait_for(lk, std::chrono::milliseconds(50));
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    LINOH_C_GUARD_END(0)
}

// ---- v5.4 F3'（借鉴 ScaleFabric 算-传紧耦合）：异步发送 ----
// 连接级惰性 flush 线程：首次 flush_async 启动，10ms 节拍 flush 直至
// has_pending_data 清除后静默等待；endpoint free 时随连接统一停止。
int linoh_connection_flush_async(linoh_connection_t *c) {
    LINOH_C_GUARD_BEGIN
    if (!c || !c->conn) return -1;
    if (c->closed.load() || c->async_flush_on.exchange(true)) return 0;   // 已开/已关

    linoh_connection *conn_raw = c;   // 生命周期由 ep->conns/draining 的 shared_ptr 保证
    try {
        conn_raw->async_flush_thread = std::thread([conn_raw]() {
            // 不依赖 has_pending_data：cwnd 满时 flush 发不出会被 ep-P5 语义
            // 误清标志（total_sent==0 即清）→ 依赖它会在窗口恢复前永久停滞。
            // 空转 flush（build 无数据即返回）成本可忽略。
            while (conn_raw->async_flush_on.load(std::memory_order_acquire) &&
                   !conn_raw->closed.load()) {
                linoh_connection_flush_all(conn_raw, 256);   // 2ms 节拍 ×256 包≈100MB/s 上限
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });
    } catch (...) {
        conn_raw->async_flush_on.store(false, std::memory_order_release);
        return -1;
    }
    return 0;
    LINOH_C_GUARD_END(-1)
}

// [FIX 2026-08-14] 重置 stream 的 send_offset 为 0
// 用于 PP 推理场景：master 在同一个 stream 上发送多条独立消息，
// 每条消息应从 offset=0 开始，对端通过隐式重置正确接收。
void linoh_stream_reset_send_offset(linoh_stream_t *s) {
    if (!s || !s->stream) return;
    std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
    s->stream->reset_send_offset();
}

void linoh_stream_reset_recv(linoh_stream_t *s) {
    if (!s || !s->stream) return;
    std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
    s->stream->reset_recv_state();
}

// [FIX 2026-08-14] 抑制/恢复 Stream::recv 的 implicit reset。
// win-worker 读取 FORWARD binary 帧（hidden_state）期间调用 suppress=1，
// 防止 HEARTBEAT_ACK retransmission 触发 implicit reset 破坏 binary 数据。
// 读取完成后调用 suppress=0 恢复，确保下一条 JSON 帧能正确触发隐式重置。
// 线程安全：suppress_implicit_reset_ 为 std::atomic<bool>，可直接 store。
void linoh_stream_suppress_reset(linoh_stream_t *s, int suppress) {
    if (!s || !s->stream) return;
    s->stream->set_suppress_implicit_reset(suppress != 0);
}

void linoh_stream_finish(linoh_stream_t *s) {
    if (!s || !s->stream) return;
    s->stream->finish_send();
}

int linoh_stream_is_finished(const linoh_stream_t *s) {
    if (!s || !s->stream) return 0;
    return s->stream->send_finished() ? 1 : 0;
}

int linoh_stream_is_closed(const linoh_stream_t *s) {
    if (!s || !s->stream) return 0;
    return s->stream->is_closed() ? 1 : 0;
}

// v1.5.0.2.3: 查询对端是否已发送 FIN
// 实现：直接代理到 endpoint::Stream::fin_received()，无需任何新字段
// 线程安全：endpoint::Stream::fin_received_ 是 bool 字段，由 recv_thread 写入，
//           读取无锁（POSIX x86/ARM 自然原子，写后读可见性靠应用层同步）
int linoh_stream_fin_received(const linoh_stream_t *s) {
    if (!s || !s->stream) return 0;
    return s->stream->fin_received() ? 1 : 0;
}

// v1.5.0.2.3: 动态切换全局日志级别
// 包装 linoh::util::log::set_level()，0=Trace, 1=Debug, 2=Info, 3=Warn, 4=Error
// 线程安全：atomic<int> store，可在任意线程调用
void linoh_set_log_level(int level) {
    if (level < 0) level = 0;
    if (level > 4) level = 4;
    auto lvl = static_cast<linoh::util::log::Level>(level);
    linoh::util::log::set_level(lvl);
}

// ============================================================================
// v1.5.0.3: F3 OOS 主动通知 API 实现
// ============================================================================
//
// 内部使用 endpoint::Stream::oos_size_bytes() / oos_first_gap() / set_oos_callback()
// 等方法。线程安全由 stream_mu_ 锁保证（OOS buffer 在 recv_thread 修改，
// 应用层在 linoh_stream_read 同一线程或独立线程读取 OOS 状态）。
//
// 设计：直接代理 C++ 内部 API，不做 O(N) 拷贝或额外锁等待。

size_t linoh_stream_oos_size(const linoh_stream_t *s) {
    if (!s || !s->stream) return 0;
    std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
    return s->stream->oos_size_bytes();
}

int linoh_stream_oos_first_gap(const linoh_stream_t *s,
                                uint64_t *out_offset,
                                size_t *out_size) {
    if (!s || !s->stream) return 0;
    std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
    std::uint64_t off_v = 0;
    std::size_t sz_v = 0;
    bool has = s->stream->oos_first_gap(&off_v, &sz_v);
    if (has) {
        if (out_offset) *out_offset = off_v;
        if (out_size)   *out_size   = sz_v;
    }
    return has ? 1 : 0;
}

namespace {
// C 回调 → endpoint::Stream::OosCallback 的桥接
// 接收 C ABI 的 linoh_on_oos_threshold_fn，转发到 endpoint::Stream::OosCallback
void oos_callback_bridge(void *user_data,
                          std::uint64_t first_gap_offset,
                          std::size_t first_gap_size,
                          std::size_t oos_total_bytes) {
    // user_data 实际是 linoh_c_oos_callback_payload 指针，包含 C 回调和 C user_data
    struct Payload {
        linoh_stream_t *s;
        linoh_on_oos_threshold_fn cb;
        void *c_user_data;
    };
    auto *p = reinterpret_cast<Payload*>(user_data);
    if (p && p->cb) {
        p->cb(p->s, first_gap_offset, first_gap_size, oos_total_bytes, p->c_user_data);
    }
}
}  // namespace

// C 回调注册：用堆上 Payload 持有 C 回调 + C user_data
// 注意：Payload 生命周期由 linoh_c 内部管理，clear 时一并释放。
// 当前实现：每次 set 都 new 一个 Payload，clear 时 delete。
// 如需高性能场景，可改为 stream handle 扩展（暂未实现以减小爆炸半径）。
struct linoh_oos_payload_t {
    linoh_stream_t *s;
    linoh_on_oos_threshold_fn cb;
    void *c_user_data;
};

void linoh_stream_set_oos_callback(linoh_stream_t *s,
                                   linoh_on_oos_threshold_fn cb,
                                   void *user_data,
                                   size_t threshold_bytes) {
    if (!s || !s->stream) return;
    std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
    if (cb == nullptr) {
        // 等价于 clear
        s->stream->clear_oos_callback();
        // 释放旧 payload（如果存在）
        if (s->oos_payload) {
            delete reinterpret_cast<linoh_oos_payload_t*>(s->oos_payload);
            s->oos_payload = nullptr;
        }
        return;
    }
    // 释放旧 payload（覆盖注册场景）
    if (s->oos_payload) {
        delete reinterpret_cast<linoh_oos_payload_t*>(s->oos_payload);
    }
    auto *payload = new linoh_oos_payload_t{s, cb, user_data};
    s->oos_payload = payload;
    s->stream->set_oos_callback(&oos_callback_bridge, payload, threshold_bytes);
}

void linoh_stream_clear_oos_callback(linoh_stream_t *s) {
    if (!s || !s->stream) return;
    std::lock_guard<std::mutex> lk(s->conn->stream_mutex());
    s->stream->clear_oos_callback();
    if (s->oos_payload) {
        delete reinterpret_cast<linoh_oos_payload_t*>(s->oos_payload);
        s->oos_payload = nullptr;
    }
}

void linoh_stream_free(linoh_stream_t *s) {
    if (!s) return;
    // v1.5.0.3: 释放 OOS 回调 payload（如果注册了但未显式 clear）
    if (s->oos_payload) {
        // 不调 endpoint::clear_oos_callback()：shared_ptr 析构时 Stream 也会析构
        delete reinterpret_cast<linoh_oos_payload_t*>(s->oos_payload);
        s->oos_payload = nullptr;
    }
    delete s;
}

// ============================================================================
// Connection API
// ============================================================================

static linoh_conn_state_t map_state(endpoint::ConnState s) {
    using CS = endpoint::ConnState;
    switch (s) {
        case CS::Initial:     return LINOH_CONN_INITIAL;
        case CS::Handshake:   return LINOH_CONN_HANDSHAKE;
        case CS::Established:  return LINOH_CONN_ESTABLISHED;
        case CS::Closing:     return LINOH_CONN_CLOSING;
        case CS::Draining:    return LINOH_CONN_DRAINING;
        case CS::Closed:      return LINOH_CONN_CLOSED;
        default:               return LINOH_CONN_CLOSED;
    }
}

// 检测连接状态变化并触发 on_state_cb（修复 2026-07-17）
// 在 recv_thread 的每次 handle_packet 之后调用
// 之前 on_state_cb 从未被调用，导致 worker 永远等不到 LINOH_CONN_ESTABLISHED
static void notify_state_if_changed(struct linoh_endpoint *ep, linoh_connection_t *lc) {
    if (!ep || !lc || !lc->conn) return;
    endpoint::ConnState cur = lc->conn->state();
    if (cur == lc->last_notified_state) return;
    lc->last_notified_state = cur;
    if (ep->on_state_cb) {
        linoh_conn_state_t cs = map_state(cur);
        LINOH_INFO("linoh_c: state changed to ", (int)cs, " - invoking on_state_cb");
        ep->on_state_cb(lc, (int)cs, ep->user_data.load());
    }
}

linoh_conn_state_t linoh_connection_state(const linoh_connection_t *c) {
    if (!c || !c->conn) return LINOH_CONN_CLOSED;
    return map_state(c->conn->state());
}

const linoh_endpoint_id_t *linoh_connection_peer_id(const linoh_connection_t *c) {
    if (!c || !c->conn) return nullptr;
    return reinterpret_cast<const linoh_endpoint_id_t*>(&c->conn->peer_id());
}

// v5.1.0 (K-LINOH-PEERMISMATCH)
int linoh_connection_peer_authenticated(const linoh_connection_t *c) {
    if (!c || !c->conn) return 0;
    return c->conn->peer_authenticated() ? 1 : 0;
}

const char *linoh_connection_alpn(const linoh_connection_t *c) {
    if (!c || !c->conn) return "";
    return c->conn->alpn().c_str();
}

// v1.5 P1-2: 引用计数管理（避免 self_ref UAF）
//
// 背景：cluster win-worker 在多线程场景下，调用方可能在线程 A 持有 conn 句柄，
// 同时线程 B 调用 linoh_endpoint_free。旧实现中 conn 由 ep->conns 唯一持有，
// 一旦 ep 析构，conn 立即释放，线程 A 后续访问触发 UAF。
//
// 本实现引入显式引用计数：ep->conns 始终持有 1 份 refcount，调用方 retain
// 时 +1，release 时 -1，但归零时不立即释放（仍由 ep->conns 持有 +1）。
// 这样调用方在 release 之前能安全访问 conn，对 ep 的析构时机更宽容。
//
// 真实的多 owner 引用计数需要 shared_ptr 改造 linoh_connection_t，
// 那是 v2.0 的工作；本接口仅作防御性 API 暴露。
void linoh_connection_retain(linoh_connection_t *conn) {
    if (!conn) return;
    int prev = conn->refcount.fetch_add(1, std::memory_order_relaxed);
    LINOH_DEBUG("linoh_c: retain conn refcount ", prev, "->", prev + 1);
}

void linoh_connection_release(linoh_connection_t *conn) {
    if (!conn) return;
    int prev = conn->refcount.fetch_sub(1, std::memory_order_relaxed);
    int now = prev - 1;
    LINOH_DEBUG("linoh_c: release conn refcount ", prev, "->", now);
    // 注意：refcount 归零不立即释放，仍由 ep->conns 持有（最低水位 1）。
    // 这避免外部 release 把 refcount 误清零导致 conn 被提前销毁。
    if (now <= 0) {
        LINOH_WARN("linoh_c: release dropped refcount to ", now,
                   " (retained by ep->conns, ignoring)");
    }
}

int linoh_connection_refcount(const linoh_connection_t *conn) {
    if (!conn) return 0;
    return conn->refcount.load(std::memory_order_relaxed);
}

void linoh_connection_stats(const linoh_connection_t *c,
                           uint64_t *packets_sent,
                           uint64_t *packets_received,
                           uint64_t *bytes_sent,
                           uint64_t *bytes_received) {
    if (!c || !c->conn) {
        if (packets_sent) *packets_sent = 0;
        if (packets_received) *packets_received = 0;
        if (bytes_sent) *bytes_sent = 0;
        if (bytes_received) *bytes_received = 0;
        return;
    }
    auto st = c->conn->stats();
    if (packets_sent) *packets_sent = st.packets_sent;
    if (packets_received) *packets_received = st.packets_received;
    if (bytes_sent) *bytes_sent = st.bytes_sent;
    if (bytes_received) *bytes_received = st.bytes_received;
}

// O1.2: 对端能力掩码（自动压缩降级矩阵输入）
linoh_error_t linoh_connection_set_peer_capabilities(linoh_connection_t *c,
                                                      uint32_t mask) {
    LINOH_C_GUARD_BEGIN
    if (!c || !c->conn) return LINOH_ERR_PARAM;
    c->conn->set_peer_capabilities(mask);
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_connection_get_peer_capabilities(const void *c,
                                                      uint32_t *out_mask) {
    LINOH_C_GUARD_BEGIN
    if (!out_mask) return LINOH_ERR_PARAM;
    if (!c || !((const linoh_connection_t *)c)->conn) {
        *out_mask = 0;
        return LINOH_OK;
    }
    *out_mask = ((const linoh_connection_t *)c)->conn->peer_capabilities();
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

// O3: 连接统计 v2（丢失/重传计数，供 FEC 自适应控制器喂数）
linoh_error_t linoh_connection_stats_v2(const linoh_connection_t *c,
                                         uint64_t *out_lost_packets,
                                         uint64_t *out_retransmitted) {
    LINOH_C_GUARD_BEGIN
    if (!c || !c->conn) {
        if (out_lost_packets) *out_lost_packets = 0;
        if (out_retransmitted) *out_retransmitted = 0;
        return LINOH_OK;
    }
    auto st = c->conn->stats();
    if (out_lost_packets) *out_lost_packets = st.lost_packets;
    if (out_retransmitted) *out_retransmitted = st.retransmitted_packets;
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

void linoh_connection_close(linoh_connection_t *c, uint16_t error_code, const char *reason) {
    if (!c || c->closed.exchange(true)) return;
    if (c->conn) c->conn->close(error_code, reason ? std::string(reason) : std::string{});
}

// P4-A-3: Immediate close — 跳过 draining period
void linoh_connection_close_immediate(linoh_connection_t *c, uint16_t error_code, const char *reason) {
    if (!c || c->closed.exchange(true)) return;
    if (c->conn) c->conn->close_immediate(error_code, reason ? std::string(reason) : std::string{});
}

void linoh_connection_free(linoh_connection_t *c) {
    if (!c) return;
    linoh_connection_close(c, 0, nullptr);
    // v5.4 F3': 停异步 flush 线程（close 置 closed 后循环自然退出，join 防悬垂）
    if (c->async_flush_on.exchange(false)) {
        if (c->async_flush_thread.joinable()) c->async_flush_thread.join();
    }
    // 修复（2026-07-18）：C-API 返回原始指针，但 endpoint->conns 仍持有 shared_ptr，
    // 直接 delete 会导致双重释放/堆损坏。先在持有锁的情况下将 shared_ptr 移出映射表，
    // 让它在作用域结束时安全释放；recv_thread 中的本地 shared_ptr 副本可保证对象
    // 在仍被使用时不会提前销毁。
    // P4 fix(2026-07-20): 用保存的 conn_key 直接 find + erase，
    // 替代 O(N) 遍历查找。O(log N)（std::map）或 O(1)（unordered_map）。
    //
    // v1.5.0.2.4 teardown 析构竞争修复：
    //   旧实现 `auto sp = std::move(it->second); conns.erase(it); (void)sp;` 会让 sp
    //   在离开作用域时立即析构 linoh_connection_t → 立即触发 endpoint::Connection
    //   析构（~Connection 内部 join timeout_thread/heartbeat_thread）。但此时
    //   recv_thread 仍持有 `auto lc = it->second` 局部 shared_ptr，正在执行
    //   `lc->conn->handle_packet()` —— linoh_connection_t 提前销毁导致 lc 局部
    //   变量访问已析构对象的成员 → ACCESS_VIOLATION 0xC0000005。
    //
    //   修复：移出 conns 后 push 到 ep->draining 队列。draining 中的 shared_ptr
    //   在 linoh_endpoint_free 中、join recv_thread 之后才被清理，确保 in-flight
    //   的 handle_packet 完成前 linoh_connection_t 不会被析构。
    if (c->endpoint && c->has_conn_key) {
        std::shared_ptr<linoh_connection> extracted;
        {
            std::lock_guard<std::mutex> lk(c->endpoint->mu);
            auto it = c->endpoint->conns.find(c->conn_key);
            if (it != c->endpoint->conns.end() && it->second.get() == c) {
                extracted = std::move(it->second);  // 引用计数 1（map:0, extracted:1）
                c->endpoint->conns.erase(it);        // map 节点删除，引用计数仍 1
            }
            // ep-M4 (v1.7.0.8): 同步删除 addr_to_conn_key_ 反向映射，保持与 conns 一致。
            // 若不删除，反向映射会残留悬挂 key，后续查找命中后 conns.find 返回 end，
            // 回退到（已删除的）find_if 路径，虽功能正确但浪费一次 hash 查找。
            if (c->has_addr_key) {
                c->endpoint->addr_to_conn_key_.erase(c->addr_key);
            }
        }
        // 移入 draining 队列，由 linoh_endpoint_free 在 join recv_thread 之后清理
        if (extracted) {
            std::lock_guard<std::mutex> dk(c->endpoint->draining_mu);
            c->endpoint->draining.push_back(std::move(extracted));
        }
        c->has_conn_key = false;
        c->has_addr_key = false;
    }
}

linoh_stream_t *linoh_connection_open_stream(linoh_connection_t *c) {
    if (!c || !c->conn) return nullptr;
    auto st = c->conn->open_stream();
    auto *s = new linoh_stream_t{};
    s->parent = c;
    s->conn = c->conn;
    s->stream = st;
    return s;
}

linoh_stream_t *linoh_connection_accept_stream(linoh_connection_t *c) {
    if (!c || !c->conn) return nullptr;
    auto st = c->conn->accept_stream();
    if (!st) return nullptr;
    auto *s = new linoh_stream_t{};
    s->parent = c;
    s->conn = c->conn;
    s->stream = st;
    return s;
}

// v5.4 F6: ICMP reset 信号归属——记到"最近发送且最近无收包"的 Outbound 连接
//（活连接持续有回包被排除；victim 无任何收包且持续发送 → 唯一候选）。
// 信号到达即调用（recvfrom 10054 分支），不等巡检 tick——快速收敛。
static void f6_attribute_reset(struct linoh_endpoint * ep, double now_ms) {
    if (!ep) return;
    std::vector<std::shared_ptr<linoh_connection>> snapshot;
    {
        std::lock_guard<std::mutex> lk(ep->mu);
        snapshot.reserve(ep->conns.size());
        for (auto & kv : ep->conns) snapshot.push_back(kv.second);
    }
    const bool ep_relay_ok = ep->relay_active.load(std::memory_order_acquire);
    std::shared_ptr<linoh_connection> victim;
    double newest = -1.0;
    for (auto & lc : snapshot) {
        if (!lc || !lc->conn || lc->closed.load()) continue;
        if (lc->conn->direction() != endpoint::Direction::Outbound) continue;
        if (lc->conn->state() != endpoint::ConnState::Established) continue;
        if (now_ms - lc->last_send_ms >= 5000.0) continue;          // 最近有发送
        if (lc->conn->last_activity_age_ms() < 2000.0) continue;    // 最近有收包=活连接，排除
        if (lc->last_send_ms > newest) { newest = lc->last_send_ms; victim = lc; }
    }
    if (!victim) return;
    ++victim->reset_streak;
    LINOH_WARN("[K-F6] udp reset signal attributed to conn ",
               victim->conn->peer_id().fmt_short(),
               " reset_streak=", victim->reset_streak);
    if (victim->reset_streak >= linoh_connection::kResetSwitchThreshold) {
        victim->reset_streak = 0;
        ++victim->path_switch_count;
        const int8_t cur = (victim->path_override >= 0)
            ? victim->path_override : (ep_relay_ok ? 1 : 0);
        victim->path_override = (cur == 1) ? 0 : 1;
        LINOH_WARN("[K-F6] path switch #", victim->path_switch_count,
                   " conn=", victim->conn->peer_id().fmt_short(),
                   " -> ", victim->path_override == 1 ? "RELAY" : "DIRECT",
                   " (reset-driven)");
    }
}

size_t linoh_connection_flush(linoh_connection_t *c) {
    if (!c || !c->conn || c->sock == INVALID_SOCKET) return 0;
    // 【v4.8.3 崩溃防护】连接已 Closed/Draining 时跳过 flush，防止
    // 连接清理路径中 send_mu 所有者线程已终止导致 pthread_mutex_lock 断言失败
    // (SIGABRT: __pthread_mutex_lock_full: Assertion `e != ESRCH || !robust' failed)
    if (c->conn->state() == endpoint::ConnState::Closed ||
        c->conn->state() == endpoint::ConnState::Draining) {
        return 0;
    }
    std::lock_guard<std::mutex> lk(c->send_mu);

    size_t total_sent = 0;

    // 调试日志（2026-07-17 Stage E.2）：详细输出 peer_addr 以排查 master→worker 发送问题
    char peer_ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &c->peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
    int peer_port = ntohs(c->peer_addr.sin_port);

    // [FIX 2026-08-14] 当 relay_active 为 true 时，数据发送到 relay_proxy_port
    // 根因：linoh endpoint 的 sendto 默认使用 peer_addr（对端公网地址），
    //       公网 UDP 通信丢包率极高（>50%），导致大量 packets lost 和 OOS gap。
    // 修复：relay_active 时将 sendto 目标改为 127.0.0.1:relay_proxy_port，
    //       relay_send_thread 从 relay_proxy_sock 读取数据后通过 WebSocket(TCP)
    //       转发给 relay server，relay server 再转发给对端。
    //       TCP 传输无 UDP 丢包问题，确保数据可靠到达。
    //
    // [FIX K-PYRO-015 2026-09-15] relay 重定向仅对 Outbound 连接生效。
    // 根因：hub 配置 HUB_RELAY_URLS 时 relay_active=true，节点经直连（UDP:9003
    //       白名单放行）入站建连后，hub 的回包仍被 endpoint 级 relay 重定向到
    //       127.0.0.1:relay_proxy_port——而节点已不再挂 relay，包在 relay 侧
    //       被丢弃（实测 hub 收 Initial 建连成功、egress 到节点公网 0 包）。
    // 修复：入站连接（Inbound）的对端地址就是它真实到达的源地址，回包按
    //       peer_addr 直发；relay 重定向只保留给本端主动发起的出站连接
    //       （出站连接的对端经 relay 中转而来，peer_addr 是 relay 视角地址）。
    sockaddr_in send_addr = c->peer_addr;
    bool use_relay = false;
    const bool conn_is_outbound =
        (c->conn->direction() == endpoint::Direction::Outbound);
    const bool ep_relay_ok = conn_is_outbound && c->endpoint &&
        c->endpoint->relay_active.load(std::memory_order_acquire);
    // v5.4 F6: 发送目标三态——连接级 path_override 覆盖 endpoint 全局：
    //   -1 跟随全局（v5.3.1 既有行为，默认零变化）/ 0 强制 direct / 1 强制 relay
    const bool relay_effective = ep_relay_ok && (c->path_override >= 0 ? c->path_override == 1 : true);
    if (relay_effective) {
        send_addr.sin_family = AF_INET;
        send_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        send_addr.sin_port = htons(c->endpoint->relay_proxy_port);
        use_relay = true;
    }
    // v5.4 F6: 发送时刻（recvfrom reset 信号的归属判定，steady 时钟）
    c->last_send_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    // v5.4 F6: 发送失败计数与路径翻转——连续 kPathSwitchThreshold 次失败即切换
    // 发送目标（direct↔relay）。Linux 上 sendto 报 ECONNREFUSED 直接触发；
    // Windows 上由 recvfrom 10054 信号经巡检归属（见 patrol）。
    auto note_send_result = [c, ep_relay_ok](bool ok) {
        if (ok) { c->send_fail_streak = 0; return; }
        if (++c->send_fail_streak < linoh_connection::kPathSwitchThreshold) return;
        c->send_fail_streak = 0;
        ++c->path_switch_count;
        const int8_t cur = (c->path_override >= 0) ? c->path_override
                                                   : (ep_relay_ok ? 1 : 0);
        c->path_override = (cur == 1) ? 0 : 1;
        LINOH_WARN("[K-F6] path switch #", c->path_switch_count,
                   " conn=", c->conn ? c->conn->peer_id().fmt_short() : "?",
                   " -> ", c->path_override == 1 ? "RELAY" : "DIRECT");
    };
    // [DEBUG 2026-08-14] WARN级别日志：确认flush是否使用relay路径
    static std::atomic<bool> s_relay_flush_logged{false};
    if (use_relay && !s_relay_flush_logged.exchange(true)) {
        LINOH_WARN("[linoh-flush] relay path ACTIVE, sending to 127.0.0.1:",
                   c->endpoint->relay_proxy_port, " instead of peer");
    }

    // 1) 先发送握手响应字节（如果有）—— 修复握手不回应的 bug（2026-07-17）
    //    handle_packet 后 pending_flight_ 中累积了待发回对端的 ServerHello/CertVerify/Finished
    auto flight = c->conn->take_handshake_flight();
    if (!flight.empty()) {
        LINOH_DEBUG("linoh_c: flush: sending handshake flight ", flight.size(),
                    " bytes to ", peer_ip, ":", peer_port,
                    use_relay ? " (via relay)" : "");
        int sent = sendto(c->sock, (const char*)flight.data(), (int)flight.size(), 0,
                          (sockaddr*)&send_addr, sizeof(send_addr));
        LINOH_DEBUG("linoh_c: flush: handshake sendto returned ", sent,
                    (sent < 0 ? " errno=" + std::to_string(errno) : ""));
        if (sent > 0) {
            total_sent += static_cast<size_t>(sent);
            // v5.4 F7: 路径占比计数
            c->conn->record_pkt_path(use_relay);
            note_send_result(true);   // v5.4 F6
        } else {
            note_send_result(false);  // v5.4 F6: sendto 失败（Linux ECONNREFUSED 等）
        }
    }

    // 2) 然后构建并发送 1-RTT 包（stream 数据）
    // K-LINOH-PERF-001 fix: send_buf 从 2048 增大到 9200（jumbo MTU 9000 + 200 余量）。
    //   build_1rtt_packet 已修复：payload_space 限制为 current_max_packet_size()，
    //   不会构建超 MTU 大包。MTU=1280 时每包 ~1230B（与旧一致），MTU=9000 时每包 ~8900B（7x 提升）。
    //   旧值 2048 导致 87KB hidden_state 需 71+ 包，增大后 MTU=9000 时仅需 ~10 包。
    c->send_buf.resize(9200);
    std::size_t n = c->conn->build_1rtt_packet(
        std::span<uint8_t>(c->send_buf.data(), c->send_buf.size()));
    if (n > 0) {
        // [FIX 2026-08-14] 大帧 WARN 日志 — 确认 tensor stream 数据是否通过 relay 发送
        if (n > 1000) {
            LINOH_WARN("[linoh-flush] sending large 1-RTT ", n, " bytes ",
                       use_relay ? "(via relay)" : "(via direct)");
        }
        int sent = sendto(c->sock, (const char*)c->send_buf.data(), (int)n, 0,
                          (sockaddr*)&send_addr, sizeof(send_addr));
        if (n > 1000 && sent <= 0) {
            LINOH_WARN("[linoh-flush] large 1-RTT sendto FAILED, sent=", sent,
                       " errno=", errno);
        }
        if (sent > 0) {
            total_sent += static_cast<size_t>(sent);
            // v5.4 F7: 路径占比计数
            c->conn->record_pkt_path(use_relay);
            note_send_result(true);   // v5.4 F6
        } else {
            note_send_result(false);  // v5.4 F6
        }
    }
    // ep-P5 (v1.7.0.8): flush 排空后清除 pending 标志。
    //   如果本次 flush 没有发送任何数据（total_sent == 0），说明 send_ buffer
    //   和 handshake flight 都已排空，清除标志。否则保持 true，下次 poll 继续 flush。
    if (total_sent == 0) {
        c->has_pending_data.store(false, std::memory_order_release);
    }
    return total_sent;
}

// v1.7.1.0: 循环 flush 直到清空，包间无 sleep。
// 根因：单次 flush 只发一个 1-RTT 包（≤2048B），73KB+ hidden_state 需 40+ 轮，
//       上层若逐轮 flush+1ms sleep 会引入等量延迟（200 轮 = 200ms+）。
// 实现：复用 linoh_connection_flush（内部持 send_mu 锁，握手 flight 首轮后自然为空），
//       最后一轮返回 0 时 flush 内部已清除 has_pending_data 标志。
size_t linoh_connection_flush_all(linoh_connection_t *c, size_t max_packets) {
    if (!c || !c->conn || c->sock == INVALID_SOCKET) return 0;
    if (max_packets == 0) max_packets = 512;
    size_t total = 0;
    for (size_t i = 0; i < max_packets; ++i) {
        size_t n = linoh_connection_flush(c);
        if (n == 0) break;
        total += n;
    }
    return total;
}

int linoh_connection_submit_packet(linoh_connection_t *c,
                                  const uint8_t *pkt, size_t pkt_len) {
    LINOH_C_GUARD_BEGIN  // A5: 异常守卫
    if (!c || !c->conn || !pkt || pkt_len == 0) return -1;
    c->conn->handle_packet(util::Bytes(std::span<const uint8_t>(pkt, pkt_len)));
    return 0;
    LINOH_C_GUARD_END(-1)
}

// ============================================================================
// Endpoint API
// ============================================================================

linoh_endpoint_t *linoh_endpoint_create(const linoh_endpoint_config_t *config) {
    if (!config) { set_error("null config"); return nullptr; }
    if (!config->alpn || config->alpn[0] == '\0') { set_error("alpn required"); return nullptr; }

#ifdef _WIN32
    WSADATA wd;
    static std::atomic<bool> wsa_init{false};
    if (!wsa_init.exchange(true)) {
        if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
            set_error("WSAStartup failed"); return nullptr;
        }
    }
#endif

    auto *ep = new linoh_endpoint_t{};
    ep->alpn = config->alpn;
    ep->user_data.store(config->user_data);
    // K-LINOH-PERF-001: 从配置加载本地期望 MTU（0 表示用默认 1280）
    ep->local_preferred_mtu = (config->local_preferred_mtu > 0) ? config->local_preferred_mtu : 1280;
    // K-LINOH-READBLK-001 (v5.3.1): 连接活性巡检配置。
    //   语义：0 = 用默认值（旧代码 memset/零初始化 struct 的调用方自动获得修复）；
    //        UINT32_MAX = 显式关闭对应机制（完全恢复 v5.3.0 行为，灰度开关）。
    ep->idle_timeout_ms = (config->idle_timeout_ms == 0) ? 30000 :
                          ((config->idle_timeout_ms == UINT32_MAX) ? 0 : config->idle_timeout_ms);
    ep->keepalive_ms    = (config->keepalive_interval_ms == 0) ? 10000 :
                          ((config->keepalive_interval_ms == UINT32_MAX) ? 0 : config->keepalive_interval_ms);
    // v5.5 F6.2: ACK 空窗路径切换阈值（0=关闭；非 0 原样生效，建议 ≥4×RTT）
    ep->path_ack_timeout_ms = config->path_ack_timeout_ms;

    // 【多模态隧道】解析 path_strategy_name（v4.8.0 新增）
    //   - 为 NULL 或空时默认 "prefer-direct"（P2P 直连优先，relay 兜底）
    //   - 与 relay_urls 配合实现多模态隧道：直连优先生效，relay 作为 fallback 路径
    //   - 启用后 PathMigrationManager 按策略选路，relay_urls 作为 fallback 路径
    {
        const char *strategy_name = config->path_strategy_name;
        if (!strategy_name || !strategy_name[0]) {
            strategy_name = "prefer-direct";  // 默认：直连优先，relay 兜底
        }
        ep->path_strategy = protocol::create_strategy_by_name(strategy_name);
        if (ep->path_strategy) {
            LINOH_INFO("[linoh-multimodal] path_strategy='", strategy_name,
                       "' enabled (", ep->path_strategy->name(), ")");
        } else {
            LINOH_WARN("[linoh-multimodal] unknown path_strategy_name='", strategy_name,
                       "', falling back to RttBasedStrategy");
        }
    }

    auto sk_bytes = std::span<const uint8_t>(config->secret_key.bytes, LINOH_KEY_SIZE);
    ep->secret_key = base::SecretKey::from_bytes(sk_bytes);

    ep->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ep->sock == INVALID_SOCKET) {
        set_error("socket() failed"); delete ep; return nullptr;
    }

    int reuse = 1;
    setsockopt(ep->sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    // [FIX 2026-08-13] 增大 UDP 接收缓冲区到 16MB，防止 relay 路径高速传输时丢包
    // 默认 Windows UDP 缓冲区仅 8-64KB，tensor shard 传输时容易溢出
    // v2: 4MB → 16MB，638KB hidden_state + FEC 冗余约 1.2MB，4MB 不够
    int rcvbuf = 16 * 1024 * 1024;
    setsockopt(ep->sock, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(rcvbuf));
    int sndbuf = 16 * 1024 * 1024;
    setsockopt(ep->sock, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(sndbuf));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config->udp_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(ep->sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        set_error("bind() failed"); closesocket(ep->sock); delete ep; return nullptr;
    }

    if (config->udp_port == 0) {
        struct sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        getsockname(ep->sock, (sockaddr*)&bound, &len);
        ep->local_port = ntohs(bound.sin_port);
    } else {
        ep->local_port = config->udp_port;
    }

    unsigned long nonblock = 1;
#ifdef _WIN32
    ioctlsocket(ep->sock, FIONBIO, &nonblock);
#else
    int flags = fcntl(ep->sock, F_GETFL, 0);
    fcntl(ep->sock, F_SETFL, flags | O_NONBLOCK);
#endif

    ep->recv_buf.resize(65536);
    ep->running.store(true);

    ep->recv_thread = std::thread([ep]() {
        struct sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        LINOH_INFO("linoh_c recv_thread started, sock=", (int)ep->sock);
        // [FIX 2026-08-14] 诊断：recv_thread 包计数器，确认 relay 注入的包是否到达
        uint64_t recv_pkt_count = 0;
        // K-LINOH-READBLK-001 (v5.3.1): 巡检节拍（500ms tick，仅空闲路径执行）
        // 单调时钟 helper（connection.cpp 的 now_ms_steady 为文件局部，此处等价实现）
        auto steady_now_ms = []() {
            return std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        };
        double last_patrol_ms = steady_now_ms();
        // K-LINOH-READBLK-001: 连接活性巡检——保活 PING + idle 超时关闭。
        // 修复"UDP 对端被 kill 无 FIN → 连接恒 ESTABLISHED → 业务读等死"。
        // 锁纪律：mu 下快照 shared_ptr 列表，锁外做探测/关闭（close/flush 有自己的锁）。
        auto patrol = [ep](double now_ms) {
            std::vector<std::shared_ptr<linoh_connection>> snapshot;
            {
                std::lock_guard<std::mutex> lk(ep->mu);
                snapshot.reserve(ep->conns.size());
                for (auto & kv : ep->conns) snapshot.push_back(kv.second);
            }
            const bool ep_relay_ok = ep->relay_active.load(std::memory_order_acquire);
            for (auto & lc : snapshot) {
                if (!lc || !lc->conn || lc->closed.load()) continue;
                try {
                    if (ep->keepalive_ms > 0 &&
                        lc->conn->needs_keepalive(now_ms)) {
                        lc->conn->request_ping();            // 置 ping_pending_，flush 时随 1-RTT 发出
                        linoh_connection_flush(lc.get());
                    }
                    if (ep->idle_timeout_ms > 0 &&
                        lc->conn->check_idle_timeout(now_ms)) {
                        LINOH_WARN("[K-READBLK] idle timeout (", ep->idle_timeout_ms,
                                   "ms) closing conn, peer=", lc->conn->peer_id().fmt_short());
                        // Immediate 模式：跳过 draining 直接 Closed；Connection::close
                        // 内部会 mark_conn_dead 所属流并触发 on_close。
                        lc->conn->close(0, "idle timeout", endpoint::Connection::CloseMode::Immediate);
                    }
                } catch (...) {
                    // 巡检不因单连接异常中断（LINOH_C_GUARD 同款纪律）
                }
            }
            // v5.4 F6: Windows ICMP 不可达归属——recvfrom 10054 信号（2s 内未消费）
            // 记到"最近发送且最近无收包"的 Outbound 连接（活连接持续有回包被排除；
            // victim 无任何收包且持续发送 → 唯一候选）
            double reset_at = ep->last_udp_reset_ms.load(std::memory_order_acquire);
            if (reset_at > 0.0 && now_ms - reset_at < 2000.0) {
                ep->last_udp_reset_ms.store(0.0, std::memory_order_release);   // 消费防重复
                f6_attribute_reset(ep, now_ms);   // v5.4 F6: patrol 兜底归属
            }
            // v5.5 F6.2: ACK 空窗路径切换——持续发送但连续 path_ack_timeout_ms
            // 无任何 ACK → 判定主路径劣化翻转。不依赖 ICMP（Windows 节流），
            // 双平台一致。单次即切（持续发送+超窗无 ACK 是强信号）；防误伤
            // 三条件：曾收到过 ACK（last_ack>0，排除握手期）、空窗期确有发送
            // （last_send 在窗内）、连接 Outbound+Established。
            if (ep->path_ack_timeout_ms > 0) {
                const double ack_to = (double)ep->path_ack_timeout_ms;
                for (auto & lc : snapshot) {
                    if (!lc || !lc->conn || lc->closed.load()) continue;
                    if (lc->conn->direction() != endpoint::Direction::Outbound) continue;
                    if (lc->conn->state() != endpoint::ConnState::Established) continue;
                    const double last_ack = lc->conn->last_ack_seen_ms();
                    if (last_ack <= 0.0) continue;                       // 从未收过 ACK：不判
                    if (now_ms - last_ack <= ack_to) continue;           // ACK 健康
                    if (now_ms - lc->last_send_ms > ack_to) continue;    // 空窗期没在发：不判
                    ++lc->path_switch_count;
                    const bool ep_relay_ok2 =
                        ep->relay_active.load(std::memory_order_acquire);
                    const int8_t cur = (lc->path_override >= 0)
                        ? lc->path_override : (ep_relay_ok2 ? 1 : 0);
                    lc->path_override = (cur == 1) ? 0 : 1;
                    LINOH_WARN("[K-F62] ACK gap ", (int)ep->path_ack_timeout_ms,
                               "ms, path switch #", lc->path_switch_count,
                               " conn=", lc->conn->peer_id().fmt_short(),
                               " -> ", lc->path_override == 1 ? "RELAY" : "DIRECT");
                }
            }
            // 兜底唤醒 read_ex 等待者（状态变化经由 tick 粒度感知，≤500ms）
            { std::lock_guard<std::mutex> lk(ep->io_cv_mu); ep->io_cv.notify_all(); }
        };
        while (ep->running.load()) {
            int n = recvfrom(ep->sock, (char*)ep->recv_buf.data(),
                             (int)ep->recv_buf.size(), 0,
                             (sockaddr*)&from, &from_len);
            if (n <= 0) {
                // v5.4 F6: Windows ICMP 不可达报在 recvfrom（10054）——记信号供巡检归属
                if (n == SOCKET_ERROR) {
                    int e = WSAGetLastError();
                    if (e == WSAECONNRESET || e == WSAECONNREFUSED || e == ECONNREFUSED) {
                        ep->last_udp_reset_ms.store(steady_now_ms(),
                                                    std::memory_order_release);
                        // v5.4 F6: 信号到达即归属（不等 500ms 巡检 tick，快速收敛）
                        f6_attribute_reset(ep, steady_now_ms());
                    }
                }
                // K-LINOH-READBLK-001: 空闲期执行巡检 tick（500ms 节拍）
                double now = steady_now_ms();
                // v5.5 F6.2: ACK 空窗通道启用时 tick 细化到 200ms（快切时延粒度）
                const double patrol_interval =
                    (ep->path_ack_timeout_ms > 0 &&
                     ep->path_ack_timeout_ms < 400.0) ? 200.0 : 500.0;
                if (now - last_patrol_ms >= patrol_interval) {
                    last_patrol_ms = now;
                    patrol(now);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                continue;
            }

            recv_pkt_count++;
            // [诊断] 前5个包 + 每100个包输出 WARN 日志
            if (recv_pkt_count <= 5 || recv_pkt_count % 100 == 0) {
                LINOH_WARN("[linoh-recv] pkt #", recv_pkt_count, " n=", n,
                           " from=", inet_ntop_safe(from.sin_addr),
                           ":", ntohs(from.sin_port),
                           " local_port=", ep->local_port,
                           " first_byte=0x", std::hex, (unsigned)ep->recv_buf[0], std::dec);
            }

            std::span<const uint8_t> wire(ep->recv_buf.data(), static_cast<size_t>(n));

            protocol::PacketParser parser(wire);
            auto pkt = parser.parse();
            if (!pkt) {
                LINOH_WARN("linoh_c: failed to parse packet n=", n,
                           " first_byte=0x", std::hex, (unsigned)ep->recv_buf[0], std::dec);
                from_len = sizeof(from);
                continue;
            }

            auto &hdr = pkt->header;
            std::vector<uint8_t> dcid_key(hdr.dcid().data().data(),
                                          hdr.dcid().data().data() + hdr.dcid().len());

            LINOH_INFO("linoh_c: parsed type=", (int)hdr.type(),
                       " dcid=", hdr.dcid().fmt_short(),
                       " scid=", hdr.scid().fmt_short(),
                       " dcid_len=", (int)hdr.dcid().len(),
                       " conns_count=", ep->conns.size());

            // ep-M1 (v1.7.0.8): 收紧 ep->mu 锁粒度——锁内仅查找/创建/插入 conn，
            // handle_packet/flush/notify_state/on_conn_cb 移出锁外。
            // 根因：原实现在 handle_packet + linoh_connection_flush + notify_state_if_changed
            // 期间持有 ep->mu，导致所有连接的包处理串行化（即便不同 conn 之间无数据竞争），
            // 高并发下成为性能瓶颈。
            // 修复：锁内拷贝 shared_ptr 保证 conn 生命周期（draining 机制保证 in-flight
            //       期间不被析构）；重活（包解析、发送、回调）全部移出锁外。
            std::shared_ptr<linoh_connection> lc_sp;
            bool is_new_conn = false;
            {
                std::lock_guard<std::mutex> lk(ep->mu);

                // 查找连接：优先用 dcid key，否则回退到 addr 反向映射
                auto it = ep->conns.find(dcid_key);
                if (it != ep->conns.end()) {
                    lc_sp = it->second;
                    LINOH_DEBUG("linoh_c: dispatching to existing conn (dcid match)");
                } else {
                    // v4.3.0 M21 fix: Initial 包始终创建新连接，不走 addr_to_conn_key_
                    // 回退查找。否则同一源地址的第二个连接（如 worker 返回路径）的
                    // Initial 会被误路由到已有 PP 链连接，导致返回数据丢失。
                    // 注意：1-RTT+dcid_len=0 包仍走 addr_to_conn_key_ 查找，因为同一
                    // 连接的后续 1-RTT 包必须路由到已建好的连接，而非每次创建新连接。
                    bool is_initial = (hdr.type() == protocol::PacketType::Initial);

                    if (!is_initial) {
                        // ep-M4 (v1.7.0.8): 用 addr_to_conn_key_ 反向映射 O(1) 查找，
                        // 替代原 O(n) find_if 全表扫描。
                        // 根因：dcid 查找失败时回退 find_if 遍历 conns，连接数多时每包 O(N)。
                        // 修复：维护 addr(sin_addr+sin_port) → conn_key 的 unordered_map，
                        //       查找路径变为 O(1) hash + O(log N) conns.find(key)。
                        auto addr_key = compute_addr_key(from);
                        auto addr_it = ep->addr_to_conn_key_.find(addr_key);
                        LINOH_INFO("linoh_c: addr_lookup key=0x", std::hex, addr_key, std::dec,
                                   " from=", inet_ntop_safe(from.sin_addr), ":", ntohs(from.sin_port),
                                   " map_size=", ep->addr_to_conn_key_.size(),
                                   " found=", (addr_it != ep->addr_to_conn_key_.end()) ? 1 : 0);
                        if (addr_it != ep->addr_to_conn_key_.end()) {
                            auto conn_it = ep->conns.find(addr_it->second);
                            if (conn_it != ep->conns.end()) {
                                lc_sp = conn_it->second;
                                LINOH_INFO("linoh_c: dispatching to existing conn (addr_to_conn_key_ match)");
                            } else {
                                // 理论不应发生（linoh_connection_free 同步删除两表），
                                // 防御性清理悬挂的反向映射 key
                                ep->addr_to_conn_key_.erase(addr_it);
                            }
                        }
                    }

                    if (!lc_sp) {
                if (hdr.type() == protocol::PacketType::Initial) {
                    endpoint::Connection::Config cfg;
                    // B1 fix(2026-07-20): 使用 endpoint 的长期身份密钥，确保 TLS 1.3
                    // 双向认证时节点身份固定可验证；原实现随机生成导致身份认证失效。
                    cfg.secret_key = ep->secret_key;
    cfg.local_preferred_mtu = ep->local_preferred_mtu;  // K-LINOH-PERF-001
    // K-LINOH-READBLK-001 (v5.3.1): 贯通巡检参数（check_idle_timeout/needs_keepalive 读 cfg_）
    cfg.idle_timeout = std::chrono::milliseconds(ep->idle_timeout_ms);
    cfg.keepalive_interval = std::chrono::milliseconds(ep->keepalive_ms);
                    cfg.local_cid = hdr.scid();
                    cfg.remote_cid = hdr.scid();
                    cfg.direction = endpoint::Direction::Inbound;
                    // v4.3.0 M21: 从 Initial token 提取 ALPN（客户端通过 token 携带 ALPN）
                    // PSK fast-complete 模式跳过 TLS 握手，ALPN 无法通过正常协商传递
                    if (!hdr.token().empty()) {
                        cfg.alpn = std::string(
                            reinterpret_cast<const char*>(hdr.token().data()),
                            hdr.token().size());
                    } else {
                        cfg.alpn = ep->alpn;
                    }

                    // [FIX 2026-08-14] inbound 连接也需注入 path_strategy
                    // 根因：master 被动接受 worker 连接时，path_strategy_enabled 未启用，
                    //       导致 PreferRelayStrategy 不生效，master 通过 P2P 直连发送数据，
                    //       公网 UDP 通信丢包严重。
                    // 修复：在 inbound 连接创建时也注入 path_strategy，与 outbound 一致。
                    if (ep->path_strategy) {
                        cfg.path_strategy_enabled = true;
                        cfg.path_strategy = ep->path_strategy;
                    }

                    auto cpp_conn = std::make_shared<endpoint::Connection>(std::move(cfg));
                    LINOH_INFO("linoh_c: new inbound conn from ", hdr.scid().fmt_short(),
                              " on_conn_cb=", (void*)ep->on_conn_cb,
                              " on_stream_cb=", (void*)ep->on_stream_cb);

                    // v1.5.0.1 E2E stress: 在创建 inbound conn 后立即 force PSK Established，
                    // 因为 linoh 1.4/1.5 简化握手 B9 hardening 让服务端 conn 跳过 TLS 1.3 AKE，
                    // 客户端必须同步跳到 Established 才能处理后续 1-RTT stream 数据。
                    // （与服务端 connection.cpp:281 临时 B9 bypass 对称修改）
                    cpp_conn->force_psk_established();
                    // v5.1.0 (K-LINOH-PEERMISMATCH): 服务端回包携带本端身份帧，
                    // 让客户端 outbound conn 也能获得已验证的对端 EndpointId。
                    // 客户端身份在下方 handle_packet(Initial) 时验签设置 peer_id_。
                    cpp_conn->send_psk_identity();

                    /// 创建 C-API 连接包装对象
                    auto lc = std::make_shared<linoh_connection_t>();
                    lc->sock = ep->sock;
                    lc->conn = cpp_conn;
                    lc->peer_addr = from;
                    lc->endpoint = ep;
                    lc->recv_buf.resize(65536);
                    lc->send_buf.resize(65536);

                    /// 注册 stream 回调：转发到 C-API 的 on_stream_cb
                    /// 捕获原始指针以打破 shared_ptr 循环引用（connection -> cpp_conn -> lambda -> shared_ptr<connection>）
                    /// 修复（2026-07-19）：必须在 handle_packet 前注册，否则 PSK fast-complete
                    /// 时若包内含 STREAM 帧，新 stream 的 on_stream_ 回调会因 null 而丢失。
                    cpp_conn->on_stream([ep, lc_raw = lc.get()](std::shared_ptr<endpoint::Stream> s) {
                        // v3.2.1 P1: Direct Return 入站拦截（MASTER 端 pp-llm/1 ResultPP[DirectReturn]）
                        // 命中则路由到 return slot，不触发用户 on_stream_cb
                        if (c_try_handle_direct_return_stream(ep, s)) return;
                        LINOH_INFO("linoh_c: stream callback id=", (unsigned long long)s->id());
                        if (!ep->on_stream_cb) {
                            LINOH_WARN("linoh_c: on_stream_cb is null - skipping");
                            return;
                        }
                        auto *ls = new linoh_stream_t{};
                        ls->parent = lc_raw;
                        ls->conn = lc_raw->conn;
                        ls->stream = s;
                        ep->on_stream_cb(ls, ep->user_data.load());
                    });

                    // ep-M1 (v1.7.0.8): conns 插入 + accept_q.push 留在锁内（保护 map/queue），
                    // handle_packet 移到锁外执行。原顺序为 handle_packet → 插入 conns，
                    // 现调整为插入 conns → 锁外 handle_packet。安全性：on_stream 回调用
                    // lc_raw 指针不查 conns；handle_packet 期间 conn 已在 conns 中可被查找。
                    auto scid_data = hdr.scid().data();
                    std::vector<uint8_t> scid_key(scid_data.data(),
                                                    scid_data.data() + scid_data.size());
                    ep->conns[scid_key] = lc;
                    // P4 fix(2026-07-20): 同步保存 key 供 O(1) 删除
                    lc->conn_key = scid_key;
                    lc->has_conn_key = true;

                    // ep-M4 (v1.7.0.8): 同步插入 addr_to_conn_key_ 反向映射
                    auto new_addr_key = compute_addr_key(from);
                    ep->addr_to_conn_key_[new_addr_key] = scid_key;
                    lc->addr_key = new_addr_key;
                    lc->has_addr_key = true;
                    LINOH_INFO("linoh_c: INSERT addr_key=0x", std::hex, new_addr_key, std::dec,
                               " from=", inet_ntop_safe(from.sin_addr), ":", ntohs(from.sin_port),
                               " map_size=", ep->addr_to_conn_key_.size(),
                               " (Initial path)");

                    ep->accept_q.push(lc.get());

                    lc_sp = lc;
                    is_new_conn = true;
                } else if (hdr.type() == protocol::PacketType::OneRtt &&
                           hdr.dcid().len() == 0) {
                    // 方案 A（2026-07-19）：1-RTT 短包头 + dcid_len=0 的 worker 端包
                    // 现象：worker 端 linoh 已"认为"握手完成（0-RTT 票据或内部状态），
                    //       直接发 1-RTT short header（dcid_len=0），从未发过 Initial。
                    // 旧逻辑走 unknown packet type 静默丢弃，导致 linoh 永远连不上。
                    // 修复：主动创建 inbound conn（PSK fast-complete 模式），强制进入 Established，
                    //       让 worker 的 1-RTT stream 数据流入 master 业务层。
                    endpoint::Connection::Config cfg;
                    // B1 fix(2026-07-20): 使用 endpoint 的长期身份密钥（同上 Initial 分支）
                    cfg.secret_key = ep->secret_key;
    cfg.local_preferred_mtu = ep->local_preferred_mtu;  // K-LINOH-PERF-001
    // K-LINOH-READBLK-001 (v5.3.1): 贯通巡检参数（check_idle_timeout/needs_keepalive 读 cfg_）
    cfg.idle_timeout = std::chrono::milliseconds(ep->idle_timeout_ms);
    cfg.keepalive_interval = std::chrono::milliseconds(ep->keepalive_ms);
                    cfg.local_cid = protocol::ConnectionId::generate();
                    cfg.remote_cid = protocol::ConnectionId();
                    cfg.direction = endpoint::Direction::Inbound;
                    cfg.alpn = ep->alpn;
                    cfg.handshake.psk_mode = true;  // 强制 PSK 模式

                    auto cpp_conn = std::make_shared<endpoint::Connection>(std::move(cfg));
                    LINOH_INFO("linoh_c: 1-RTT short header dcid_len=0 - creating inbound conn ",
                              "from ", inet_ntop_safe(from.sin_addr), ":", ntohs(from.sin_port),
                              " on_conn_cb=", (void*)ep->on_conn_cb,
                              " on_stream_cb=", (void*)ep->on_stream_cb);
                    // 关键修复（2026-07-19）：先 PSK fast-complete 跳到 Established，
                    //          再注册 on_stream 回调，最后才 handle_packet 处理 1-RTT payload。
                    // 顺序：force → register callback → handle_packet
                    // 否则 handle_packet 解析 STREAM 帧时 on_stream_ 为 null，新创建的 stream
                    // 不会触发上层 C-API on_stream_cb。
                    cpp_conn->force_psk_established();
                    // v5.1.0 (K-LINOH-PEERMISMATCH): 同 Initial 分支，回包带本端身份
                    cpp_conn->send_psk_identity();

                    auto lc = std::make_shared<linoh_connection_t>();
                    lc->sock = ep->sock;
                    lc->conn = cpp_conn;
                    lc->peer_addr = from;
                    lc->endpoint = ep;
                    lc->recv_buf.resize(65536);
                    lc->send_buf.resize(65536);

                    cpp_conn->on_stream([ep, lc_raw = lc.get()](std::shared_ptr<endpoint::Stream> s) {
                        // v3.2.1 P1: Direct Return 入站拦截（MASTER 端 pp-llm/1 ResultPP[DirectReturn]）
                        if (c_try_handle_direct_return_stream(ep, s)) return;
                        LINOH_INFO("linoh_c: stream callback id=", (unsigned long long)s->id());
                        if (!ep->on_stream_cb) {
                            LINOH_WARN("linoh_c: on_stream_cb is null - skipping");
                            return;
                        }
                        auto *ls = new linoh_stream_t{};
                        ls->parent = lc_raw;
                        ls->conn = lc_raw->conn;
                        ls->stream = s;
                        ep->on_stream_cb(ls, ep->user_data.load());
                    });

                    // ep-M1 (v1.7.0.8): 同上 Initial 分支，conns 插入 + accept_q.push
                    // 留在锁内，handle_packet 移到锁外。
                    // P7 fix(2026-07-20): 用 peer_addr.sin_addr(4B) + peer_port(2B) 共 6 字节作为 key。
                    // 旧实现仅用 0xFF + peer_port（3 字节），同一 NAT 后多设备若源端口相同会冲突。
                    // 注：sin_addr 已是网络字节序，sin_port 也是网络字节序，直接 memcpy 即可保持一致。
                    std::vector<uint8_t> zero_dcid_key;
                    zero_dcid_key.resize(6);
                    std::memcpy(zero_dcid_key.data(), &from.sin_addr.s_addr, 4);
                    std::memcpy(zero_dcid_key.data() + 4, &from.sin_port, 2);
                    ep->conns[zero_dcid_key] = lc;
                    // P4 fix(2026-07-20): 同步保存 key 供 O(1) 删除
                    lc->conn_key = zero_dcid_key;
                    lc->has_conn_key = true;

                    // ep-M4 (v1.7.0.8): 同步插入 addr_to_conn_key_ 反向映射
                    auto new_addr_key = compute_addr_key(from);
                    ep->addr_to_conn_key_[new_addr_key] = zero_dcid_key;
                    lc->addr_key = new_addr_key;
                    lc->has_addr_key = true;

                    ep->accept_q.push(lc.get());

                    lc_sp = lc;
                    is_new_conn = true;
                } else {
                    LINOH_DEBUG("linoh_c: unknown packet type=", (int)hdr.type(),
                               " - discarding (dcid=", hdr.dcid().fmt_short(), ")");
                }
                    }  // end if (!lc_sp)
                }
            }  // ep->mu 释放

            // ep-M1 (v1.7.0.8): 锁外处理——handle_packet / flush / notify / on_conn_cb
            // shared_ptr lc_sp 保证 conn 生命周期；draining 机制保证即便 linoh_connection_free
            // 被并发调用，conn 也不会在 handle_packet 期间被析构（shared_ptr 引用计数 > 0）。
            if (lc_sp) {
                lc_sp->conn->handle_packet(util::Bytes(wire));
                // K-LINOH-READBLK-001: 收包即活性（record_activity 此前无任何调用方，
                // last_activity_ms_ 恒 0 → 巡检首 tick 必误杀健康连接）
                lc_sp->conn->record_activity(steady_now_ms());
                // K-LINOH-READBLK-001 (v5.3.1): 数据到达唤醒 read_ex 等待者
                { std::lock_guard<std::mutex> nlk(ep->io_cv_mu); ep->io_cv.notify_all(); }
                // 自动 flush：把握手响应/1-RTT 发回对端（修复 2026-07-17）
                linoh_connection_flush(lc_sp.get());
                // 状态变化通知（修复 2026-07-17）：检测 Established 并触发 on_state_cb
                notify_state_if_changed(ep, lc_sp.get());
                if (is_new_conn) {
                    // 新连接回调（锁外调用，避免用户回调长时间持锁）
                    if (ep->on_conn_cb) {
                        LINOH_INFO("linoh_c: invoking on_conn_cb");
                        ep->on_conn_cb(lc_sp.get(), ep->user_data.load());
                    } else {
                        LINOH_WARN("linoh_c: on_conn_cb is null - skipping");
                    }
                }
            }

            from_len = sizeof(from);
        }
    });

    // ── 【硬件规定】linoh 原生 relay 初始化 ──────────────────────────────
    // 当配置了 relay_urls 时，启动 linoh 原生 relay client 作为本地 UDP 代理，
    // 替代外部 relay_bridge 进程。endpoint 核心逻辑无需修改。
    // 不依赖 asio — 使用裸 TCP socket + ws_client.hpp + stride.hpp 实现 relay 协议
    if (config->relay_url_count > 0 && config->relay_urls) {
        LINOH_INFO("[linoh-relay] relay_urls configured, count=", config->relay_url_count);

        // 1. 创建本地 UDP 代理 socket（relay_proxy_sock）
        ep->relay_proxy_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (ep->relay_proxy_sock == INVALID_SOCKET) {
            LINOH_ERROR("[linoh-relay] failed to create relay_proxy_sock");
        } else {
            int reuse = 1;
            setsockopt(ep->relay_proxy_sock, SOL_SOCKET, SO_REUSEADDR,
                       (const char*)&reuse, sizeof(reuse));

            // [FIX 2026-08-13] 增大 relay proxy UDP 缓冲区到 16MB
            // relay_send_thread 从此 socket 读取数据转发到 WebSocket(TCP)
            // 若缓冲区太小（默认 8-64KB），linoh endpoint 高速发送时 UDP 包被丢弃
            // 导致 linoh 协议检测到序列号缺口，触发大量重传和 "packets lost" 告警
            // v2: 4MB → 16MB，配合 ep->sock 的 16MB 缓冲区
            int rcvbuf = 16 * 1024 * 1024;
            setsockopt(ep->relay_proxy_sock, SOL_SOCKET, SO_RCVBUF,
                       (const char*)&rcvbuf, sizeof(rcvbuf));
            int sndbuf = 16 * 1024 * 1024;
            setsockopt(ep->relay_proxy_sock, SOL_SOCKET, SO_SNDBUF,
                       (const char*)&sndbuf, sizeof(sndbuf));

            struct sockaddr_in proxy_addr{};
            proxy_addr.sin_family = AF_INET;
            proxy_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            proxy_addr.sin_port = 0;  // 随机端口

            if (bind(ep->relay_proxy_sock, (sockaddr*)&proxy_addr, sizeof(proxy_addr)) != 0) {
                LINOH_ERROR("[linoh-relay] failed to bind relay_proxy_sock");
                closesocket(ep->relay_proxy_sock);
                ep->relay_proxy_sock = INVALID_SOCKET;
            } else {
                // 获取实际绑定的端口
                struct sockaddr_in bound{};
                socklen_t blen = sizeof(bound);
                getsockname(ep->relay_proxy_sock, (sockaddr*)&bound, &blen);
                ep->relay_proxy_port = ntohs(bound.sin_port);
                LINOH_INFO("[linoh-relay] relay_proxy_sock bound to 127.0.0.1:",
                           ep->relay_proxy_port);

                // 设置非阻塞
                unsigned long nonblock = 1;
            #ifdef _WIN32
                ioctlsocket(ep->relay_proxy_sock, FIONBIO, &nonblock);
            #else
                int flags_proxy = fcntl(ep->relay_proxy_sock, F_GETFL, 0);
                fcntl(ep->relay_proxy_sock, F_SETFL, flags_proxy | O_NONBLOCK);
            #endif

                // 2. 解析 relay_peer_id_hex（如果配置）
                if (config->relay_peer_id_hex && strlen(config->relay_peer_id_hex) == 64) {
                    auto hex_val = [](char c) -> int {
                        if (c >= '0' && c <= '9') return c - '0';
                        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                        return -1;
                    };
                    bool parse_ok = true;
                    for (int i = 0; i < 32; ++i) {
                        int hi = hex_val(config->relay_peer_id_hex[i*2]);
                        int lo = hex_val(config->relay_peer_id_hex[i*2+1]);
                        if (hi < 0 || lo < 0) { parse_ok = false; break; }
                        ep->relay_peer_id.data()[i] = (uint8_t)((hi << 4) | lo);
                    }
                    if (parse_ok) {
                        LINOH_INFO("[linoh-relay] peer_id parsed: ",
                                   ep->relay_peer_id.fmt_short());
                    } else {
                        LINOH_WARN("[linoh-relay] failed to parse relay_peer_id_hex");
                        ep->relay_peer_id = base::EndpointId{};
                    }
                }

                // 3. 连接到 relay server（尝试每个 URL，直到成功）
                bool connected = false;
                for (uint32_t i = 0; i < config->relay_url_count && !connected; ++i) {
                    if (!config->relay_urls[i]) continue;
                    std::string url_str(config->relay_urls[i]);
                    LINOH_INFO("[linoh-relay] trying relay URL: ", url_str);

                    // 解析 URL：格式 ws://host:port 或 wss://host:port
                    std::string host;
                    uint16_t rport = 0;
                    std::string scheme;
                    if (url_str.substr(0, 5) == "ws://") {
                        scheme = "ws";
                        host = url_str.substr(5);
                    } else if (url_str.substr(0, 6) == "wss://") {
                        scheme = "wss";
                        host = url_str.substr(6);
                    } else {
                        LINOH_WARN("[linoh-relay] unsupported scheme in URL: ", url_str);
                        continue;
                    }
                    auto colon = host.rfind(':');
                    if (colon != std::string::npos) {
                        rport = (uint16_t)std::stoi(host.substr(colon + 1));
                        host = host.substr(0, colon);
                    } else {
                        rport = (scheme == "wss") ? 443 : 80;
                    }
                    if (scheme == "wss") {
                        LINOH_WARN("[linoh-relay] wss:// not supported in C API yet, skipping");
                        continue;
                    }

                    // TCP 连接到 relay server
                    ep->relay_tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (ep->relay_tcp_sock == INVALID_SOCKET) {
                        LINOH_ERROR("[linoh-relay] failed to create TCP socket");
                        continue;
                    }

                    // [FIX 2026-08-14] 在 connect 前设置 SO_KEEPALIVE（确保生效）
                    {
                        int keepalive = 1;
                        setsockopt(ep->relay_tcp_sock, SOL_SOCKET, SO_KEEPALIVE,
                                   (const char*)&keepalive, sizeof(keepalive));
                    }

                    struct sockaddr_in relay_addr{};
                    relay_addr.sin_family = AF_INET;
                    relay_addr.sin_port = htons(rport);
                    if (inet_pton(AF_INET, host.c_str(), &relay_addr.sin_addr) <= 0) {
                        LINOH_WARN("[linoh-relay] invalid host IP: ", host);
                        closesocket(ep->relay_tcp_sock);
                        ep->relay_tcp_sock = INVALID_SOCKET;
                        continue;
                    }

                    if (connect(ep->relay_tcp_sock, (sockaddr*)&relay_addr,
                                sizeof(relay_addr)) != 0) {
                        LINOH_WARN("[linoh-relay] TCP connect failed to ",
                                   host, ":", rport);
                        closesocket(ep->relay_tcp_sock);
                        ep->relay_tcp_sock = INVALID_SOCKET;
                        continue;
                    }

                    // [FIX 2026-08-14] 在 connect 成功后设置 TCP keepalive，防止 NAT 超时断开
                    {
                        int keepalive = 1;
                        setsockopt(ep->relay_tcp_sock, SOL_SOCKET, SO_KEEPALIVE,
                                   (const char*)&keepalive, sizeof(keepalive));
#ifdef _WIN32
                        DWORD dwBytesRet = 0;
                        struct tcp_keepalive ka = { 1, 15000, 5000 };
                        int ka_rc = WSAIoctl(ep->relay_tcp_sock, SIO_KEEPALIVE_VALS,
                                 &ka, sizeof(ka), NULL, 0, &dwBytesRet, NULL, NULL);
                        LINOH_WARN("[linoh-relay] TCP keepalive set after connect (rc=", ka_rc,
                                   ", 15s idle, 5s interval)");
#else
                        int idle = 15, interval = 5, count = 5;
                        setsockopt(ep->relay_tcp_sock, IPPROTO_TCP, TCP_KEEPIDLE,
                                   &idle, sizeof(idle));
                        setsockopt(ep->relay_tcp_sock, IPPROTO_TCP, TCP_KEEPINTVL,
                                   &interval, sizeof(interval));
                        setsockopt(ep->relay_tcp_sock, IPPROTO_TCP, TCP_KEEPCNT,
                                   &count, sizeof(count));
                        LINOH_WARN("[linoh-relay] TCP keepalive set after connect",
                                   " (15s idle, 5s interval, 5 probes)");
#endif
                    }

                    // WebSocket 握手
                    std::string ws_req = linoh::relay::ws_build_handshake_request(
                        host, "/", std::to_string(rport));
                    {
                        std::lock_guard<std::mutex> lk(ep->relay_send_mu);
                        send(ep->relay_tcp_sock, ws_req.data(), (int)ws_req.size(), 0);
                    }

                    // 读取 101 响应
                    std::vector<uint8_t> resp_buf;
                    resp_buf.resize(4096);
                    bool ws_ok = false;
                    int total_recv = 0;
                    for (int attempt = 0; attempt < 100 && !ws_ok; ++attempt) {
                        int n = recv(ep->relay_tcp_sock,
                                     (char*)resp_buf.data() + total_recv,
                                     (int)(resp_buf.size() - total_recv), 0);
                        if (n <= 0) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(10));
                            continue;
                        }
                        total_recv += n;
                        if (linoh::relay::ws_validate_handshake_response(
                                std::span<const uint8_t>(resp_buf.data(), total_recv))) {
                            ws_ok = true;
                        }
                        if (total_recv >= (int)resp_buf.size()) break;
                    }

                    if (!ws_ok) {
                        LINOH_WARN("[linoh-relay] WebSocket handshake failed for ", url_str);
                        closesocket(ep->relay_tcp_sock);
                        ep->relay_tcp_sock = INVALID_SOCKET;
                        continue;
                    }

                    LINOH_WARN("[linoh-relay] WebSocket connected to ", url_str);
                    connected = true;

                    // 【关键修复】HTTP 101 响应后可能紧跟 ServerChallenge 帧（同一 TCP 包）
                    // 必须将 \r\n\r\n 之后的剩余字节传递给认证握手代码，否则 ServerChallenge 丢失
                    {
                        std::string resp_str(reinterpret_cast<const char*>(resp_buf.data()), total_recv);
                        auto hdr_end = resp_str.find("\r\n\r\n");
                        if (hdr_end != std::string::npos) {
                            std::size_t body_start = hdr_end + 4;
                            if (body_start < (std::size_t)total_recv) {
                                ep->relay_leftover.assign(resp_buf.data() + body_start,
                                                          resp_buf.data() + total_recv);
                                LINOH_WARN("[linoh-relay] pre-read ", ep->relay_leftover.size(),
                                           " bytes after HTTP headers (ServerChallenge?)");
                            }
                        }
                    }
                }

                if (connected) {
                    ep->relay_running.store(true);

                    // 【关键修复】relay auth: wait ServerChallenge -> send ClientAuth -> wait ServerConfirmsAuth
                    {
                        LINOH_WARN("[linoh-relay] waiting for ServerChallenge...");
                        std::vector<uint8_t> auth_accum;
                        // 将 HTTP 响应后预读的字节作为认证握手的初始数据
                        if (!ep->relay_leftover.empty()) {
                            auth_accum = std::move(ep->relay_leftover);
                            ep->relay_leftover.clear();
                        }
                        std::array<uint8_t, 4096> auth_buf{};
                        bool auth_confirmed = false;
                        auto auth_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                        while (std::chrono::steady_clock::now() < auth_deadline && ep->relay_running.load() && !auth_confirmed) {
                            // 先尝试解码已有数据（可能来自 HTTP 升级后预读的 ServerChallenge）
                            bool need_more = false;
                            while (!auth_accum.empty()) {
                                auto ws_res = linoh::relay::ws_decode_frame(std::span<const uint8_t>(auth_accum.data(), auth_accum.size()));
                                if (ws_res.need_more || ws_res.invalid) { if (ws_res.invalid) auth_accum.clear(); need_more = true; break; }
                                if (!ws_res.ok) { need_more = true; break; }
                                auth_accum.erase(auth_accum.begin(), auth_accum.begin() + ws_res.bytes_consumed);
                                auto &ws_f = ws_res.frame;
                                if (ws_f.opcode == linoh::relay::WsOpcode::Ping) {
                                    auto pong_ws = linoh::relay::ws_encode_pong_frame(std::span<const uint8_t>(ws_f.payload.data(), ws_f.payload.size()));
                                    std::lock_guard<std::mutex> lk0(ep->relay_send_mu);
                                    send(ep->relay_tcp_sock, (const char*)pong_ws.data(), (int)pong_ws.size(), 0);
                                    continue;
                                }
                                if (ws_f.opcode != linoh::relay::WsOpcode::Binary) continue;
                                auto stride_f = linoh::relay::decode_frame(std::span<const uint8_t>(ws_f.payload.data(), ws_f.payload.size()));
                                if (!stride_f) continue;
                                if (stride_f->type == linoh::relay::FrameType::ServerChallenge) {
                                    auto sc = linoh::relay::decode_server_challenge(std::span<const uint8_t>(stride_f->payload.data(), stride_f->payload.size()));
                                    if (!sc) { LINOH_WARN("[linoh-relay] failed to decode ServerChallenge"); break; }
                                    auto client_auth = linoh::relay::sign_challenge(*sc, ep->secret_key);
                                    auto auth_stride = linoh::relay::encode_client_auth(client_auth);
                                    auto auth_ws = linoh::relay::ws_encode_binary_frame(std::span<const uint8_t>(auth_stride.data(), auth_stride.size()));
                                    std::lock_guard<std::mutex> lk1(ep->relay_send_mu);
                                    send(ep->relay_tcp_sock, (const char*)auth_ws.data(), (int)auth_ws.size(), 0);
                                    LINOH_WARN("[linoh-relay] ClientAuth sent, endpoint_id=", client_auth.endpoint_id.fmt_short());
                                } else if (stride_f->type == linoh::relay::FrameType::ServerConfirmsAuth) {
                                    LINOH_WARN("[linoh-relay] auth confirmed by server");
                                    auth_confirmed = true;
                                    break;
                                } else if (stride_f->type == linoh::relay::FrameType::ServerDeniesAuth) {
                                    LINOH_WARN("[linoh-relay] auth denied by server");
                                    break;
                                }
                            }
                            if (auth_confirmed) break;
                            // 如果 auth_accum 已空但认证未完成，继续 recv 等待 ServerConfirmsAuth
                            if (!need_more && auth_accum.empty()) {
                                // auth_accum 已处理完但认证未完成，需要更多数据
                                need_more = true;
                            }
                            if (!need_more) break;
                            // 已有数据不足，从 socket 读取更多
                            int an = recv(ep->relay_tcp_sock, (char*)auth_buf.data(), (int)auth_buf.size(), 0);
                            if (an <= 0) { std::this_thread::sleep_for(std::chrono::milliseconds(5)); continue; }
                            auth_accum.insert(auth_accum.end(), auth_buf.data(), auth_buf.data() + an);
                            while (true) {
                                auto ws_res = linoh::relay::ws_decode_frame(std::span<const uint8_t>(auth_accum.data(), auth_accum.size()));
                                if (ws_res.need_more || ws_res.invalid) { if (ws_res.invalid) auth_accum.clear(); break; }
                                if (!ws_res.ok) break;
                                auth_accum.erase(auth_accum.begin(), auth_accum.begin() + ws_res.bytes_consumed);
                                auto &ws_f = ws_res.frame;
                                if (ws_f.opcode == linoh::relay::WsOpcode::Ping) {
                                    auto pong_ws = linoh::relay::ws_encode_pong_frame(std::span<const uint8_t>(ws_f.payload.data(), ws_f.payload.size()));
                                    std::lock_guard<std::mutex> lk0(ep->relay_send_mu);
                                    send(ep->relay_tcp_sock, (const char*)pong_ws.data(), (int)pong_ws.size(), 0);
                                    continue;
                                }
                                if (ws_f.opcode != linoh::relay::WsOpcode::Binary) continue;
                                auto stride_f = linoh::relay::decode_frame(std::span<const uint8_t>(ws_f.payload.data(), ws_f.payload.size()));
                                if (!stride_f) continue;
                                if (stride_f->type == linoh::relay::FrameType::ServerChallenge) {
                                    auto sc = linoh::relay::decode_server_challenge(std::span<const uint8_t>(stride_f->payload.data(), stride_f->payload.size()));
                                    if (!sc) { LINOH_WARN("[linoh-relay] failed to decode ServerChallenge"); break; }
                                    auto client_auth = linoh::relay::sign_challenge(*sc, ep->secret_key);
                                    auto auth_stride = linoh::relay::encode_client_auth(client_auth);
                                    auto auth_ws = linoh::relay::ws_encode_binary_frame(std::span<const uint8_t>(auth_stride.data(), auth_stride.size()));
                                    std::lock_guard<std::mutex> lk1(ep->relay_send_mu);
                                    send(ep->relay_tcp_sock, (const char*)auth_ws.data(), (int)auth_ws.size(), 0);
                                    LINOH_WARN("[linoh-relay] ClientAuth sent, endpoint_id=", client_auth.endpoint_id.fmt_short());
                                } else if (stride_f->type == linoh::relay::FrameType::ServerConfirmsAuth) {
                                    LINOH_WARN("[linoh-relay] auth confirmed by server");
                                    auth_confirmed = true;
                                    break;
                                } else if (stride_f->type == linoh::relay::FrameType::ServerDeniesAuth) {
                                    LINOH_WARN("[linoh-relay] auth denied by server");
                                    break;
                                }
                            }
                        }
                        if (!auth_confirmed) { LINOH_WARN("[linoh-relay] auth not confirmed, relay may not work"); }
                    }

                    // 4. 启动 relay_recv_thread：
                    //    从 relay TCP socket 读取 WebSocket 帧 → 解码 STRIDE → 注入到 ep->sock
                    ep->relay_recv_thread = std::thread([ep]() {
                        LINOH_INFO("[linoh-relay] recv_thread started");
                        std::vector<uint8_t> ws_accum;
                        ws_accum.reserve(65536);
                        std::vector<uint8_t> recv_buf(65536);

                        while (ep->relay_running.load()) {
                            int n = recv(ep->relay_tcp_sock,
                                         (char*)recv_buf.data(),
                                         (int)recv_buf.size(), 0);
                            if (n == 0) {
                                // [FIX 2026-08-14] recv=0: graceful close by relay server
                                // 原代码仅 sleep 5ms 继续循环，导致 relay 连接已断但 relay_active
                                // 仍为 true，数据发送到死连接无响应。修复：立即标记 inactive 并退出。
                                if (ep->relay_running.load()) {
                                    LINOH_WARN("[linoh-relay] recv_thread: connection closed "
                                               "by relay server (recv=0), marking relay inactive");
                                    ep->relay_active.store(false);
                                }
                                break;
                            }
                            if (n < 0) {
                                // [FIX 2026-08-14] recv=-1: socket error (connection reset, etc.)
                                if (ep->relay_running.load()) {
                                    int err =
#ifdef _WIN32
                                        WSAGetLastError();
#else
                                        errno;
#endif
                                    LINOH_WARN("[linoh-relay] recv_thread: recv error (errno=",
                                               err, "), marking relay inactive");
                                    ep->relay_active.store(false);
                                }
                                break;
                            }

                            ws_accum.insert(ws_accum.end(),
                                            recv_buf.data(),
                                            recv_buf.data() + n);

                            // 解码 WebSocket 帧
                            while (true) {
                                auto ws_result = linoh::relay::ws_decode_frame(
                                    std::span<const uint8_t>(ws_accum.data(),
                                                              ws_accum.size()));
                                if (ws_result.need_more || ws_result.invalid) {
                                    if (ws_result.invalid) {
                                        LINOH_WARN("[linoh-relay] invalid WS frame, clearing");
                                        ws_accum.clear();
                                    }
                                    break;
                                }
                                if (!ws_result.ok) break;

                                // 消费已解析的字节
                                ws_accum.erase(ws_accum.begin(),
                                               ws_accum.begin() + ws_result.bytes_consumed);

                                auto &frame = ws_result.frame;

                                // 处理 WebSocket 帧
                                if (frame.opcode == linoh::relay::WsOpcode::Binary) {
                                    // 解码 STRIDE 帧
                                    auto stride_frame = linoh::relay::decode_frame(
                                        std::span<const uint8_t>(frame.payload.data(),
                                                                  frame.payload.size()));
                                    if (!stride_frame) continue;

                                    if (stride_frame->type ==
                                        linoh::relay::FrameType::RelayToClientDatagram) {
                                        // 解码 datagram
                                        auto dg = linoh::relay::decode_datagram(
                                            std::span<const uint8_t>(
                                                stride_frame->payload.data(),
                                                stride_frame->payload.size()));
                                        if (!dg) {
                                            LINOH_WARN("[linoh-relay] recv_thread: failed to decode datagram");
                                            continue;
                                        }
                                        // [FIX 2026-08-14] WARN 日志确认 relay_recv_thread 收到数据
                                        LINOH_WARN("[linoh-relay] recv_thread: got datagram contents_size=",
                                                   dg->contents.size(), " dst_zero=", dg->dst.is_zero());

                                        // 【关键修复 v4.8.1】动态学习 relay_peer_id
                                        // relay server 转发时，datagram.dst 被改写为发送方
                                        // endpoint_id（src 语义，见 server.cpp forward_datagram:
                                        // "out.dst = from->id; mark as the true source"）。
                                        // master 端配置 relay_peer_id_hex=nullptr，首次收到
                                        // 对端数据时从此处学习回送目标，使 ACK 能经 relay 返回。
                                        // win-worker 端已配置 relay_peer_id_hex，此处为幂等覆盖。
                                        if (!dg->dst.is_zero()) {
                                            std::lock_guard<std::mutex> lk(
                                                ep->relay_peer_id_mu);
                                            ep->relay_peer_id = dg->dst;
                                            // 【v4.8.2 诊断日志】确认动态学习成功
                                            LINOH_INFO("[linoh-relay] recv_thread learned "
                                                       "relay_peer_id=", dg->dst.fmt_short(),
                                                       " contents_size=", dg->contents.size());
                                        } else {
                                            LINOH_WARN("[linoh-relay] recv_thread dg->dst is "
                                                       "zero, cannot learn relay_peer_id");
                                        }

                                        // relay → endpoint：将 contents 注入到 ep->sock
                                        if (!dg->contents.empty()) {
                                            struct sockaddr_in target{};
                                            target.sin_family = AF_INET;
                                            target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                                            target.sin_port = htons(ep->local_port);
                                            int inject_rc = sendto(ep->relay_proxy_sock,
                                                   (const char*)dg->contents.data(),
                                                   (int)dg->contents.size(), 0,
                                                   (sockaddr*)&target,
                                                   sizeof(target));
                                            if (inject_rc <= 0) {
                                                LINOH_WARN("[linoh-relay] recv_thread: inject sendto FAILED rc=",
                                                           inject_rc, " errno=", errno,
                                                           " local_port=", ep->local_port);
                                            }
                                            // [诊断 2026-08-14] 前5次注入输出 WARN 日志，确认目标端口
                                            thread_local int inject_log_count = 0;
                                            if (inject_log_count < 5) {
                                                inject_log_count++;
                                                LINOH_WARN("[linoh-relay] inject #", inject_log_count,
                                                           " size=", dg->contents.size(),
                                                           " → 127.0.0.1:", ep->local_port,
                                                           " rc=", inject_rc);
                                            }

                                            // [FIX 2026-08-14] relay→endpoint 流量控制
                                            // 根因：relay_recv_thread 从 TCP 高速读取数据并通过 UDP
                                            //       sendto 注入到 ep->sock，若发送速率超过 linoh
                                            //       endpoint 的 poll 处理速率，ep->sock 的 16MB
                                            //       接收缓冲区会溢出，导致 UDP 包丢弃（表现为
                                            //       "packets lost" 和 OOS gap）。
                                            // 修复：基于令牌桶限制注入速率，目标 ~20MB/s，允许
                                            //       突发 2MB。hidden_state (159KB) 约 8ms 传输完。
                                            //       不影响小帧（JSON/ACK）的延迟。
                                            thread_local auto last_refill =
                                                std::chrono::steady_clock::now();
                                            thread_local double tokens = 1.0 * 1024 * 1024;
                                            const double max_tokens = 1.0 * 1024 * 1024;
                                            const double refill_rate = 5.0 * 1024 * 1024;

                                            auto now_ts = std::chrono::steady_clock::now();
                                            double elapsed_s =
                                                std::chrono::duration<double>(
                                                    now_ts - last_refill).count();
                                            last_refill = now_ts;
                                            tokens = (std::min)(max_tokens,
                                                              tokens + elapsed_s * refill_rate);

                                            double need = (double)dg->contents.size();
                                            if (tokens < need) {
                                                double wait_s = (need - tokens) / refill_rate;
                                                std::this_thread::sleep_for(
                                                    std::chrono::duration<double>(wait_s));
                                                tokens = 0.0;
                                            } else {
                                                tokens -= need;
                                            }
                                        }
                                    } else if (stride_frame->type ==
                                               linoh::relay::FrameType::Ping) {
                                        // 响应 Pong
                                        auto pong_payload = linoh::relay::decode_ping_pong_payload(
                                            std::span<const uint8_t>(
                                                stride_frame->payload.data(),
                                                stride_frame->payload.size()));
                                        if (pong_payload) {
                                            auto pong_frame = linoh::relay::encode_pong(
                                                *pong_payload);
                                            auto ws_frame = linoh::relay::ws_encode_binary_frame(
                                                std::span<const uint8_t>(pong_frame.data(),
                                                                          pong_frame.size()));
                                            std::lock_guard<std::mutex> lk(ep->relay_send_mu);
                                            send(ep->relay_tcp_sock,
                                                 (const char*)ws_frame.data(),
                                                 (int)ws_frame.size(), 0);
                                        }
                                    }
                                } else if (frame.opcode == linoh::relay::WsOpcode::Ping) {
                                    // 【关键修复】回复 WS Pong 控制帧，防止 relay server keepalive 超时断开
                                    auto pong_ws = linoh::relay::ws_encode_pong_frame(
                                        std::span<const uint8_t>(frame.payload.data(),
                                                                  frame.payload.size()));
                                    std::lock_guard<std::mutex> lk(ep->relay_send_mu);
                                    send(ep->relay_tcp_sock,
                                         (const char*)pong_ws.data(),
                                         (int)pong_ws.size(), 0);
                                } else if (frame.opcode == linoh::relay::WsOpcode::Pong) {
                                    // WS Pong 控制帧，keepalive 维持
                                    // [FIX 2026-08-14] 更新 last_pong_ms，用于 ping_thread 检测半开连接
                                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::steady_clock::now().time_since_epoch()).count();
                                    ep->last_pong_ms.store(now_ms, std::memory_order_release);
                                } else if (frame.opcode == linoh::relay::WsOpcode::Close) {
                                    LINOH_WARN("[linoh-relay] server sent Close frame");
                                    ep->relay_running.store(false);
                                    break;
                                }
                            }
                        }
                        LINOH_INFO("[linoh-relay] recv_thread stopped");
                    });

                    // 5. 启动 relay_send_thread：
                    //    从 relay_proxy_sock 读取数据 → 编码 STRIDE → 发送给 relay server
                    ep->relay_send_thread = std::thread([ep]() {
                        LINOH_INFO("[linoh-relay] send_thread started");
                        std::vector<uint8_t> buf(65536);

                        while (ep->relay_running.load()) {
                            struct sockaddr_in from{};
                            socklen_t from_len = sizeof(from);
                            int n = recvfrom(ep->relay_proxy_sock,
                                             (char*)buf.data(), (int)buf.size(), 0,
                                             (sockaddr*)&from, &from_len);
                            if (n <= 0) {
                                std::this_thread::sleep_for(
                                    std::chrono::milliseconds(2));
                                continue;
                            }

                            // 【v4.8.2 诊断日志】确认 relay_send_thread 收到 ACK 数据
                            LINOH_INFO("[linoh-relay] send_thread recv ", n,
                                       " bytes from proxy_sock, from_port=",
                                       ntohs(from.sin_port));

                            // endpoint → relay：编码 ClientToRelayDatagram → WebSocket → TCP
                            // 【v4.8.1】加锁读取 relay_peer_id（relay_recv_thread 会动态更新）
                            base::EndpointId cur_peer_id;
                            {
                                std::lock_guard<std::mutex> lk(
                                    ep->relay_peer_id_mu);
                                cur_peer_id = ep->relay_peer_id;
                            }
                            if (!cur_peer_id.is_zero()) {
                                if (n > 100) {
                                    LINOH_WARN("[linoh-relay] send_thread unicast ", n,
                                               " bytes to peer=", cur_peer_id.fmt_short());
                                }

                                linoh::relay::Datagram dg;
                                dg.dst = cur_peer_id;
                                dg.contents.assign(buf.begin(), buf.begin() + n);

                                auto stride_frame = linoh::relay::encode_client_to_relay_datagram(dg);
                                auto ws_frame = linoh::relay::ws_encode_binary_frame(
                                    std::span<const uint8_t>(stride_frame.data(),
                                                              stride_frame.size()));

                                std::lock_guard<std::mutex> lk(ep->relay_send_mu);
                                int sent = send(ep->relay_tcp_sock,
                                     (const char*)ws_frame.data(),
                                     (int)ws_frame.size(), 0);
                                if (n > 100 && sent <= 0) {
                                    LINOH_WARN("[linoh-relay] send_thread unicast send FAILED rc=",
                                               sent, " errno=", errno, " ws_frame_size=", ws_frame.size());
                                }
                            } else {
                                // [FIX 2026-08-14] relay_peer_id 为零时使用广播模式
                                //
                                // 根因：master 和 win-worker 每次启动生成新 keypair，
                                // endpoint_id 变化，win-worker 配置的 relay_peer_id_hex
                                // 可能不匹配 master 当前 endpoint_id。
                                //
                                // 修复：relay_peer_id 为零时，将 dst 设置为零（广播），
                                // relay server 将数据转发到所有连接的节点。
                                // 对端收到数据后通过动态学习机制更新 relay_peer_id，
                                // 后续通信可以使用单播模式。
                                LINOH_WARN("[linoh-relay] send_thread relay_peer_id "
                                           "is zero, using BROADCAST mode for ", n, " bytes");

                                linoh::relay::Datagram dg;
                                dg.dst = base::EndpointId{};  // zero = broadcast
                                dg.contents.assign(buf.begin(), buf.begin() + n);

                                auto stride_frame = linoh::relay::encode_client_to_relay_datagram(dg);
                                auto ws_frame = linoh::relay::ws_encode_binary_frame(
                                    std::span<const uint8_t>(stride_frame.data(),
                                                              stride_frame.size()));

                                std::lock_guard<std::mutex> lk(ep->relay_send_mu);
                                int sent = send(ep->relay_tcp_sock,
                                     (const char*)ws_frame.data(),
                                     (int)ws_frame.size(), 0);
                            }
                        }
                        LINOH_INFO("[linoh-relay] send_thread stopped");
                    });

                    // 6. 启动 Ping 保活线程（每 15s 发送一次 Ping）
                    // 防止 relay server 因空闲超时关闭连接
                    ep->relay_ping_thread = std::thread([ep]() {
                        LINOH_WARN("[linoh-relay] ping_thread started (interval=5s)");
                        int relay_fail_count = 0;  // [FIX 2026-08-13] 连续失败计数器
                        // 8 字节 Ping payload：时间戳低 8 字节
                        while (ep->relay_running.load()) {
                            // 等待 5s，但每 100ms 检查一次 relay_running 以便快速退出
                            for (int i = 0; i < 50 && ep->relay_running.load(); ++i) {
                                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            }
                            if (!ep->relay_running.load()) break;

                            // 构造 Ping payload（8 字节时间戳）
                            std::array<uint8_t, 8> ping_payload{};
                            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now().time_since_epoch()).count();
                            for (int i = 0; i < 8; ++i) {
                                ping_payload[i] = static_cast<uint8_t>(
                                    (now_ms >> (i * 8)) & 0xFF);
                            }

                            // [FIX 2026-08-14] 发送真正的 WebSocket Ping 帧（opcode 0x9），
                            // 而不是 binary 帧（opcode 0x2）。
                            // 根因：relay server 只对 WebSocket Ping 帧回复 Pong，
                            //       binary 帧不会被识别为 keepalive 请求。
                            //       之前用 ws_encode_binary_frame 封装 STRIDE Ping payload，
                            //       relay server 不回复 Pong，导致 Pong 超时。
                            auto ws_frame = linoh::relay::ws_encode_ping_frame(
                                std::span<const uint8_t>(ping_payload.data(),
                                                          ping_payload.size()));

                            std::lock_guard<std::mutex> lk(ep->relay_send_mu);
                            if (ep->relay_tcp_sock != INVALID_SOCKET) {
                                int sent = send(ep->relay_tcp_sock,
                                                (const char*)ws_frame.data(),
                                                (int)ws_frame.size(), 0);
                                if (sent <= 0) {
                                    relay_fail_count++;
                                    LINOH_WARN("[linoh-relay] ping send failed (",
                                               relay_fail_count, "/3), "
                                               "relay connection may be lost");
                                    // [FIX 2026-08-13] 连续 3 次 ping 失败（~45s），
                                    // 关闭 relay 和主连接触发上层重连重建 relay。
                                    // 根因：relay WebSocket TCP 连接断开后不会自动重建，
                                    //       上层 win-worker 只调用 linoh_endpoint_connect
                                    //       重连主 UDP 连接，不重建 relay。
                                    // 修复：关闭主 UDP socket 触发 on_close_cb，
                                    //       上层清理时释放 endpoint，下次 linoh_endpoint_create
                                    //       重建 relay WebSocket 连接。
                                    if (relay_fail_count >= 3) {
                                        LINOH_WARN("[linoh-relay] 3 consecutive ping failures, "
                                                   "marking relay as inactive for reconnect");
                                        // [FIX 2026-08-13 v2] 只设置 relay_active=false，
                                        // 不关闭 sockets（避免与其他线程竞争导致 crash）。
                                        // 上层 win-worker 检测到 relay_active=false 后，
                                        // 在清理代码中释放 endpoint 并重建 relay。
                                        ep->relay_active.store(false);
                                        break;
                                    }
                                } else {
                                    relay_fail_count = 0;  // 成功则重置计数器
                                    // [FIX 2026-08-14] Pong 超时检测：send 成功不代表连接正常
                                    // 如果距上次 Pong 超过 30s（2×15s relay server ping 间隔），认为连接半开
                                    int64_t last_pong = ep->last_pong_ms.load(std::memory_order_acquire);
                                    if (last_pong > 0) {
                                        auto cur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::steady_clock::now().time_since_epoch()).count();
                                        if (cur_ms - last_pong > 30000) {
                                            LINOH_WARN("[linoh-relay] Pong timeout (",
                                                       (cur_ms - last_pong) / 1000,
                                                       "s since last Pong), marking relay inactive");
                                            ep->relay_active.store(false);
                                            break;
                                        }
                                    }
                                }
                            } else {
                                relay_fail_count++;
                                if (relay_fail_count >= 3) {
                                    LINOH_WARN("[linoh-relay] relay_tcp_sock invalid, "
                                               "marking relay as inactive for reconnect");
                                    ep->relay_active.store(false);
                                    break;
                                }
                            }
                        }
                        LINOH_INFO("[linoh-relay] ping_thread stopped");
                    });

                    ep->relay_active.store(true);
                    // [FIX 2026-08-14] 初始化 last_pong_ms 为当前时间，
                    // 确保 Pong 超时检测能正常工作（避免 last_pong_ms=0 时检测不触发）
                    {
                        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
                        ep->last_pong_ms.store(now_ms, std::memory_order_release);
                    }
                    LINOH_WARN("[linoh-relay] relay active, proxy_port=",
                               ep->relay_proxy_port);
                } else {
                    LINOH_ERROR("[linoh-relay] failed to connect to any relay server");
                    if (ep->relay_proxy_sock != INVALID_SOCKET) {
                        closesocket(ep->relay_proxy_sock);
                        ep->relay_proxy_sock = INVALID_SOCKET;
                    }
                }
            }
        }
    }

    return ep;
}

// [FIX 2026-08-13] 查询 relay 连接是否活跃
// 上层（win-worker）在重连前调用此函数判断是否需要释放并重建 endpoint
// 返回值：true=relay 活跃（无需重建），false=relay 已断开（需重建）
bool linoh_endpoint_is_relay_active(const linoh_endpoint_t *ep) {
    if (!ep) return false;
    return ep->relay_active.load();
}

void linoh_endpoint_free(linoh_endpoint_t *ep) {
    if (!ep) return;
    ep->running.store(false);

    // 【硬件规定】清理 relay 相关资源
    // 1. 设置 relay_running=false 通知所有 relay 线程退出
    // 2. 关闭 relay_tcp_sock 以解除 recv 阻塞
    // 3. 关闭 relay_proxy_sock 以解除 recvfrom 阻塞
    // 4. join 所有 relay 线程
    ep->relay_running.store(false);

    // 关闭 TCP socket 以解除 relay_recv_thread 的 recv 阻塞
    if (ep->relay_tcp_sock != INVALID_SOCKET) {
        SOCKET tmp = ep->relay_tcp_sock;
        ep->relay_tcp_sock = INVALID_SOCKET;
        closesocket(tmp);
    }
    // 关闭 proxy socket 以解除 relay_send_thread 的 recvfrom 阻塞
    if (ep->relay_proxy_sock != INVALID_SOCKET) {
        SOCKET tmp = ep->relay_proxy_sock;
        ep->relay_proxy_sock = INVALID_SOCKET;
        closesocket(tmp);
    }

    if (ep->relay_ping_thread.joinable()) {
        ep->relay_ping_thread.join();
    }
    if (ep->relay_recv_thread.joinable()) {
        ep->relay_recv_thread.join();
    }
    if (ep->relay_send_thread.joinable()) {
        ep->relay_send_thread.join();
    }

    if (ep->sock != INVALID_SOCKET) {
        closesocket(ep->sock);
        ep->sock = INVALID_SOCKET;
    }
    if (ep->recv_thread.joinable()) {
        ep->recv_thread.join();
    }
    {
        std::lock_guard<std::mutex> dk(ep->draining_mu);
        ep->draining.clear();
    }
    {
        std::lock_guard<std::mutex> lk(ep->mu);
        ep->conns.clear();
        ep->addr_to_conn_key_.clear();
    }
    delete ep;
}

static thread_local linoh_endpoint_id_t g_ep_id_buf{};

const linoh_endpoint_id_t *linoh_endpoint_id(const linoh_endpoint_t *ep) {
    if (!ep) return nullptr;
    auto pk = ep->secret_key.public_key();
    auto pk_span = pk.as_span();
    std::memcpy(g_ep_id_buf.bytes, pk_span.data(), std::min<size_t>(pk_span.size(), 32));
    return &g_ep_id_buf;
}

uint16_t linoh_endpoint_udp_port(const linoh_endpoint_t *ep) {
    if (!ep) return 0;
    return ep->local_port;
}

void linoh_endpoint_on_connection(linoh_endpoint_t *ep, ::linoh_on_connection_fn cb) {
    if (ep) ep->on_conn_cb = reinterpret_cast<c_on_conn_fn>(cb);
}
void linoh_endpoint_on_stream(linoh_endpoint_t *ep, ::linoh_on_stream_fn cb) {
    if (ep) ep->on_stream_cb = reinterpret_cast<c_on_stream_fn>(cb);
}
void linoh_endpoint_on_conn_state(linoh_endpoint_t *ep, ::linoh_on_conn_state_fn cb) {
    if (ep) ep->on_state_cb = reinterpret_cast<c_on_state_fn>(cb);
}
void linoh_endpoint_on_close(linoh_endpoint_t *ep, ::linoh_on_close_fn cb) {
    if (ep) ep->on_close_cb = reinterpret_cast<c_on_close_fn>(cb);
}

// P5-C-1: set_user_data — 允许在 endpoint_create 之后注入或更新 user_data
// 典型场景：JNI 桥接层在 create 后才能确定 handle 指针，通过此 API 注入
// 线程安全：atomic<void*> store，与回调线程的 load() 无锁同步
void linoh_endpoint_set_user_data(linoh_endpoint_t *ep, void *user_data) {
    if (!ep) return;
    ep->user_data.store(user_data, std::memory_order_release);
}

int linoh_endpoint_poll(linoh_endpoint_t *ep) {
    if (!ep) return 0;
    int events = 0;

    // v3.8.0 biased select!: 事件优先级 close > send > accept
    //
    // 设计来源：Psyche biased select! 事件循环模式
    // 痛点：旧实现 accept → send 顺序，新连接洪峰会延迟优雅关闭与发送；
    //       且 on_close_cb 注册后从未被调用（close 事件无出口）。
    // 修复：
    //   1. close 事件最高优先级 — 检测 Closed/Draining 连接，触发 on_close_cb
    //   2. send 事件中优先级 — flush 有 pending 数据的 conn（已关闭的跳过）
    //   3. accept 事件最低优先级 — drain accept queue（新连接可延后）
    // 收益：优雅关闭不阻塞；on_close_cb 终于有调用路径；关闭连接不再被 flush。

    // 复制 shared_ptr 列表后释放 ep->mu 锁，避免与 linoh_connection_flush
    // 内部的 send_mu 锁死锁（v1.5.0.2.3 既有做法）
    std::vector<std::shared_ptr<linoh_connection_t>> conn_list;
    {
        std::lock_guard<std::mutex> lk(ep->mu);
        conn_list.reserve(ep->conns.size());
        for (auto &kv : ep->conns) {
            conn_list.push_back(kv.second);
        }
    }

    // 1. close 事件（最高优先级）
    for (auto &c : conn_list) {
        if (!c || !c->conn) continue;
        if (c->close_notified) continue;  // 已通知，不重复
        auto st = c->conn->state();
        if (st == endpoint::ConnState::Closed ||
            st == endpoint::ConnState::Draining) {
            c->close_notified = true;
            if (ep->on_close_cb) {
                ep->on_close_cb(c.get(), ep->user_data.load());
            }
            ++events;
        }
    }

    // 2. send 事件（中优先级）
    // v1.5.0.2.3: 推动所有 conn 发送 stream data（linoh_stream_write
    // 只把数据放入 send_ buffer，必须 flush 才会 build_1rtt_packet 发到 UDP）
    for (auto &c : conn_list) {
        if (!c || !c->conn) continue;
        if (c->close_notified) continue;  // 已关闭，不再 flush
        // ep-P5 (v1.7.0.8): 仅 flush 有 pending 数据的 conn，避免遍历全部 conn 锁竞争
        //   has_pending_data 在 linoh_stream_write 时置 true，flush 排空后置 false。
        //   握手 flight 不走 stream_write，但 take_handshake_flight 在 flush 内部检查，
        //   为安全起见握手阶段（非 Established）始终 flush。
        if (c->has_pending_data.load(std::memory_order_acquire) ||
            c->conn->state() != endpoint::ConnState::Established) {
            linoh_connection_flush(c.get());
        }
    }

    // 3. accept 事件（最低优先级）
    // Drain the accept queue: invoke on_conn_cb for each pending connection
    while (true) {
        linoh_connection_t *conn = nullptr;
        {
            std::lock_guard<std::mutex> lk(ep->mu);
            if (ep->accept_q.empty()) break;
            conn = ep->accept_q.front();
            ep->accept_q.pop();
        }
        if (conn && ep->on_conn_cb) {
            ep->on_conn_cb(conn, ep->user_data.load());
        }
        ++events;
    }
    return events;
}

linoh_connection_t *linoh_endpoint_accept(linoh_endpoint_t *ep) {
    if (!ep) return nullptr;
    std::lock_guard<std::mutex> lk(ep->mu);
    if (ep->accept_q.empty()) return nullptr;
    auto *lc = ep->accept_q.front();
    ep->accept_q.pop();
    return lc;
}

// v1.5 P1-1: 通用实现，支持 alpn override
//
// 与 linoh_endpoint_connect 的唯一区别：cfg.alpn 用传入的 alpn 参数
// （若 alpn 为空则回退到 ep->alpn，保持向后兼容）。
//
// ep->alpn 在本函数中始终不被修改，避免 linoh_endpoint_connect_multimodal
// 等多线程调用方的 swap 副作用。
linoh_connection_t *linoh_endpoint_connect_with_alpn(linoh_endpoint_t *ep,
                                                      const char *host,
                                                      uint16_t port,
                                                      const char *alpn) {
    if (!ep || !host) return nullptr;

    // 【硬件规定】relay 重定向：当 relay_active 时，连接到本地 relay_proxy_port
    // relay client 作为本地 UDP 代理，endpoint 发出的数据通过 relay client 中转到对端
    if (ep->relay_active.load() && ep->relay_proxy_port > 0) {
        LINOH_WARN("[linoh-relay] connect redirect: ", host, ":", port,
                   " → 127.0.0.1:", ep->relay_proxy_port);
        host = "127.0.0.1";
        port = ep->relay_proxy_port;
    }

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        return nullptr;
    }

    // 创建客户端 Connection
    endpoint::Connection::Config cfg;
    // B1 fix(2026-07-20): 出站连接同样使用 endpoint 的长期身份密钥
    cfg.secret_key = ep->secret_key;
    cfg.local_preferred_mtu = ep->local_preferred_mtu;  // K-LINOH-PERF-001
    // K-LINOH-READBLK-001 (v5.3.1): 贯通巡检参数（check_idle_timeout/needs_keepalive 读 cfg_）
    cfg.idle_timeout = std::chrono::milliseconds(ep->idle_timeout_ms);
    cfg.keepalive_interval = std::chrono::milliseconds(ep->keepalive_ms);
    cfg.local_cid = protocol::ConnectionId::generate();
    cfg.remote_cid = protocol::ConnectionId();
    cfg.direction = endpoint::Direction::Outbound;

    // 【多模态隧道】注入 path_strategy 到 Connection（v4.8.0 新增）
    //   - ep->path_strategy 非空时启用 PathSelectionStrategy 决策路径迁移
    //   - 与 relay_urls 配合：直连路径优先生效，relay 作为 fallback 路径
    //   - PathMigrationManager 接收策略后，在路径质量变化时按策略 select_primary_path
    if (ep->path_strategy) {
        cfg.path_strategy_enabled = true;
        cfg.path_strategy = ep->path_strategy;
    }
    // v1.5 P1-1: alpn 参数优先；为空回退 ep->alpn
    cfg.alpn = (alpn && alpn[0]) ? std::string(alpn) : ep->alpn;
    // v1.7.0.5 P4 (C3): 拒绝空 ALPN 连接（借鉴 iroh #4427 v1.0.3）
    // 传入 alpn 为空且 ep->alpn 也为空时，握手会静默失败，此处提前拒绝。
    if (cfg.alpn.empty()) {
        LINOH_ERROR("linoh_c: cannot connect with empty ALPN (alpn arg empty and ep->alpn empty, iroh #4427)");
        return nullptr;
    }

    // v4.3.0 M21 fix: 在 std::move(cfg) 之前保存 alpn 和 CID，用于 Initial 包构建
    // （move 后 cfg.alpn 为空，导致服务端入站连接 ALPN 协商失败）
    std::string alpn_saved = cfg.alpn;
    auto local_cid_saved = cfg.local_cid;
    auto remote_cid_saved = cfg.remote_cid;

    LINOH_INFO("[CONN-DBG] step1: before Connection ctor");
    auto cpp_conn = std::make_shared<endpoint::Connection>(std::move(cfg));
    LINOH_INFO("[CONN-DBG] step2: after Connection ctor, cpp_conn=", (void*)cpp_conn.get());

    // v1.5.0.1 E2E stress: client outbound conn 也立即 force PSK Established，
    // 因为 server 端临时 B9 bypass 让对端 conn 直接走 Established（无 CRYPTO AKE），
    // 客户端 conn 必须对称建立才能 build 1-RTT stream packets 发回 server。
    cpp_conn->force_psk_established();
    LINOH_INFO("[CONN-DBG] step3: after force_psk_established");

    // 创建 C-API 连接包装对象（使用 Endpoint 的 UDP socket）
    auto lc = std::make_shared<linoh_connection_t>();
    lc->sock = ep->sock;
    lc->conn = cpp_conn;
    lc->peer_addr = server_addr;
    lc->endpoint = ep;
    lc->recv_buf.resize(65536);
    lc->send_buf.resize(65536);
    // v1.5 P1-2: 引用计数初值 1（由 ep->conns map 持有），保留 1 不被外部 release 清零
    lc->refcount.store(1);
    LINOH_INFO("[CONN-DBG] step4: after lc setup, lc=", (void*)lc.get());

    // 注册 stream 回调（捕获原始指针以打破 shared_ptr 循环引用）
    cpp_conn->on_stream([ep, lc_raw = lc.get()](std::shared_ptr<endpoint::Stream> s) {
        // v3.2.1 P1: Direct Return 入站拦截（MASTER 端 pp-llm/1 ResultPP[DirectReturn]）
        if (c_try_handle_direct_return_stream(ep, s)) return;
        if (!ep->on_stream_cb) return;
        auto *ls = new linoh_stream_t{};
        ls->parent = lc_raw;
        ls->conn = lc_raw->conn;
        ls->stream = s;
        ep->on_stream_cb(ls, ep->user_data.load());
    });
    LINOH_INFO("[CONN-DBG] step5: after on_stream register");

    // B8 fix(2026-07-20): 注册 PING 发送回调，心跳线程通过 request_ping() +
    // on_ping_send_requested_ 触发 flush，替代开新 stream 发 RPC 的旧逻辑。
    // 捕获 weak_ptr 避免连接析构后回调访问悬空指针。
    std::weak_ptr<linoh_connection_t> lc_weak = lc;
    cpp_conn->on_ping_send_requested_ = [lc_weak]() {
        if (auto lc = lc_weak.lock()) {
            linoh_connection_flush(lc.get());
        }
    };
    LINOH_INFO("[CONN-DBG] step6: after on_ping_send_requested register");

    // 以 local_cid 作为 key（使用 move 前保存的副本）
    auto scid_data = local_cid_saved.data();
    std::vector<uint8_t> cid_key(scid_data.data(),
                                   scid_data.data() + scid_data.size());
    {
        std::lock_guard<std::mutex> lk(ep->mu);
        ep->conns[cid_key] = lc;
        // ep-M4 (v1.7.0.8): 同步插入 addr_to_conn_key_ 反向映射。
        // 出站连接的 peer_addr 是 server_addr，server 回包时若 dcid 查找失败，
        // 可通过 addr 反向映射 O(1) 找到 conn（与入站连接对称）。
        auto out_addr_key = compute_addr_key(server_addr);
        ep->addr_to_conn_key_[out_addr_key] = cid_key;
        lc->addr_key = out_addr_key;
        lc->has_addr_key = true;
    }
    LINOH_INFO("[CONN-DBG] step7: after ep->conns insert");
    // P4 fix(2026-07-20): 同步保存 key 供 O(1) 删除
    lc->conn_key = cid_key;
    lc->has_conn_key = true;

    // 构建并发送 Initial 包（建立连接）
    // v4.3.0 M21 fix: 使用 move 前保存的 alpn_saved 和 CID，避免访问 moved-from cfg
    LINOH_INFO("[CONN-DBG] step8: before make_initial");
    auto initial_hdr = protocol::PacketHeader::make_initial(
        remote_cid_saved, local_cid_saved);
    // v4.3.0 M21: 将 ALPN 放入 Initial token 字段，让服务端入站连接使用正确的 ALPN
    // （PSK fast-complete 模式跳过 TLS 握手，ALPN 无法通过正常协商传递）
    if (!alpn_saved.empty()) {
        initial_hdr.set_token(std::span<const std::uint8_t>(
            reinterpret_cast<const uint8_t*>(alpn_saved.data()),
            alpn_saved.size()));
    }
    uint8_t initial_buf[512];
    size_t initial_len = initial_hdr.serialize_to(initial_buf, sizeof(initial_buf));

    // v5.1.0 (K-LINOH-PEERMISMATCH): Initial 包尾附加 PSK_IDENTITY 帧，
    // 让服务端入站连接立即获得已验证的本端 EndpointId。
    // 必须为包内最后一个帧（rest-of-payload 解析约定）。
    {
        auto idata = cpp_conn->build_psk_identity_data();
        if (!idata.empty() && initial_len + 1 + idata.size() <= sizeof(initial_buf)) {
            initial_buf[initial_len] =
                static_cast<uint8_t>(protocol::FrameType::PSK_IDENTITY);
            ++initial_len;
            std::memcpy(initial_buf + initial_len, idata.data(), idata.size());
            initial_len += idata.size();
        } else {
            LINOH_WARN("linoh_c: PSK_IDENTITY frame does not fit in Initial buffer, "
                       "will ride first 1-RTT packet instead");
        }
    }
    // 身份帧同时标记待发：若 Initial 丢失（UDP），首个 1-RTT 包会重带
    cpp_conn->send_psk_identity();

    // [FIX 2026-08-14] Initial 包也需通过 relay 路径发送（当 relay_active 时）
    sockaddr_in initial_send_addr = server_addr;
    if (ep->relay_active.load(std::memory_order_acquire)) {
        initial_send_addr.sin_family = AF_INET;
        initial_send_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        initial_send_addr.sin_port = htons(ep->relay_proxy_port);
        LINOH_INFO("linoh_c: sending Initial pkt ", initial_len, " bytes via relay "
                   "(127.0.0.1:", ep->relay_proxy_port, ") alpn=", alpn_saved);
    } else {
        LINOH_INFO("linoh_c: sending Initial pkt ", initial_len, " bytes to ",
                  inet_ntop_safe(server_addr.sin_addr), ":", ntohs(server_addr.sin_port),
                  " alpn=", alpn_saved);
    }
    int sent = sendto(ep->sock, (const char*)initial_buf, (int)initial_len, 0,
                      (sockaddr*)&initial_send_addr, sizeof(initial_send_addr));
    LINOH_DEBUG("linoh_c: sendto returned ", sent);

    return lc.get();
}

// ============================================================================
// v3.2.0 Direct Return Path — 末节点直连回传 MASTER 的 C-API 实现
//
// return stream 连接池：按 (master_host, master_port) 复用 pp-llm/1 连接。
// 同一 MASTER 多次推理复用同一条连接，减少 dial/握手开销。
// ============================================================================

linoh_stream_t *linoh_open_return_stream(linoh_endpoint_t *ep,
                                          const char *master_host,
                                          uint16_t master_port,
                                          uint32_t stream_token) {
    if (!ep || !master_host) return nullptr;
    (void)stream_token;  // stream_token 在 linoh_send_result_direct 时写入 payload

    auto key = std::make_pair(std::string(master_host), master_port);
    std::shared_ptr<linoh_connection> lc;

    // 1) 查池：复用已有 pp-llm/1 连接
    {
        std::lock_guard<std::mutex> lk(ep->return_pool_mu);
        auto it = ep->return_pool.find(key);
        if (it != ep->return_pool.end()) lc = it->second;
    }
    // 2) 验证连接有效性；失效则移除并重新 dial
    if (lc) {
        if (lc->closed.load() || !lc->conn || lc->conn->is_closed()) {
            lc.reset();
            std::lock_guard<std::mutex> lk(ep->return_pool_mu);
            ep->return_pool.erase(key);
        }
    }
    if (!lc) {
        linoh_connection_t *raw = linoh_endpoint_connect_with_alpn(
            ep, master_host, master_port, "pp-llm/1");
        if (!raw) return nullptr;
        // 从 ep->conns 反查 shared_ptr（connect_with_alpn 已设置 conn_key）
        std::lock_guard<std::mutex> lk(ep->mu);
        if (raw->has_conn_key) {
            auto it = ep->conns.find(raw->conn_key);
            if (it != ep->conns.end()) lc = it->second;
        }
        if (!lc) return nullptr;
        std::lock_guard<std::mutex> plk(ep->return_pool_mu);
        ep->return_pool[key] = lc;
    }

    // 3) 在复用连接上 open_stream
    return linoh_connection_open_stream(lc.get());
}

int linoh_send_result_direct(linoh_endpoint_t *ep,
                              linoh_stream_t *stream,
                              uint32_t stream_token,
                              const uint8_t *result_payload,
                              size_t result_len,
                              int combined) {
    (void)ep;
    if (!stream || !stream->stream) return -1;
    if (result_len > 0 && !result_payload) return -1;

    // payload = [stream_token(4B,LE)][result_payload]
    std::vector<uint8_t> payload;
    payload.reserve(4 + result_len);
    payload.push_back(static_cast<uint8_t>(stream_token & 0xFF));
    payload.push_back(static_cast<uint8_t>((stream_token >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>((stream_token >> 16) & 0xFF));
    payload.push_back(static_cast<uint8_t>((stream_token >> 24) & 0xFF));
    payload.insert(payload.end(), result_payload, result_payload + result_len);

    // 封装为 ApplicationMessage(ResultPP, flags=DirectReturn[|EndOfStream])
    protocol::ApplicationMessage msg = protocol::ApplicationMessage::notification(
        protocol::MethodId::ResultPP,
        std::span<const uint8_t>(payload.data(), payload.size()));
    msg.flags = static_cast<uint16_t>(protocol::MessageFlags::DirectReturn);
    if (combined) {
        msg.flags |= static_cast<uint16_t>(protocol::MessageFlags::EndOfStream);
    }
    auto wire = msg.serialize();

    size_t written = linoh_stream_write(stream, wire.data(), wire.size());
    if (written == 0) return -2;
    linoh_stream_finish(stream);  // 发送 FIN，标记本 stream 结束
    return 0;
}

int linoh_send_result_direct_sharded(linoh_endpoint_t *ep,
                                      linoh_stream_t *stream,
                                      uint32_t stream_token,
                                      const uint8_t *result_payload,
                                      size_t result_len,
                                      int combined,
                                      size_t shard_size) {
    (void)ep;
    if (!stream || !stream->stream) return -1;
    if (result_len > 0 && !result_payload) return -1;
    if (shard_size == 0) shard_size = 1024;

    if (result_len == 0) {
        // 空结果：退化为单条非分片
        return linoh_send_result_direct(
            ep, stream, stream_token, result_payload, result_len, combined);
    }

    uint16_t num_shards = static_cast<uint16_t>(
        (result_len + shard_size - 1) / shard_size);
    if (num_shards == 0) num_shards = 1;

    for (uint16_t idx = 0; idx < num_shards; ++idx) {
        size_t offset = static_cast<size_t>(idx) * shard_size;
        size_t end = (std::min)(offset + shard_size, result_len);
        size_t chunk_len = end - offset;

        // payload = [stream_token(4B,LE)][shard_idx(2B,LE)][total_shards(2B,LE)][chunk]
        std::vector<uint8_t> payload;
        payload.reserve(8 + chunk_len);
        payload.push_back(static_cast<uint8_t>(stream_token & 0xFF));
        payload.push_back(static_cast<uint8_t>((stream_token >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>((stream_token >> 16) & 0xFF));
        payload.push_back(static_cast<uint8_t>((stream_token >> 24) & 0xFF));
        payload.push_back(static_cast<uint8_t>(idx & 0xFF));
        payload.push_back(static_cast<uint8_t>((idx >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(num_shards & 0xFF));
        payload.push_back(static_cast<uint8_t>((num_shards >> 8) & 0xFF));
        payload.insert(payload.end(), result_payload + offset, result_payload + end);

        protocol::ApplicationMessage msg = protocol::ApplicationMessage::notification(
            protocol::MethodId::ResultPP,
            std::span<const uint8_t>(payload.data(), payload.size()));
        msg.flags = static_cast<uint16_t>(protocol::MessageFlags::DirectReturn) |
                    static_cast<uint16_t>(protocol::MessageFlags::ResultShard);
        if (combined && idx == num_shards - 1) {
            msg.flags |= static_cast<uint16_t>(protocol::MessageFlags::EndOfStream);
        }
        auto wire = msg.serialize();
        size_t written = linoh_stream_write(stream, wire.data(), wire.size());
        if (written == 0) return -2;
    }

    linoh_stream_finish(stream);  // FIN
    return 0;
}

void linoh_close_return_stream(linoh_endpoint_t *ep, linoh_stream_t *stream) {
    (void)ep;
    // 仅释放 stream 句柄；底层连接留 return_pool 中复用
    linoh_stream_free(stream);
}

int linoh_return_stream_pool_cleanup(linoh_endpoint_t *ep) {
    if (!ep) return 0;
    int cleaned = 0;
    std::lock_guard<std::mutex> lk(ep->return_pool_mu);
    for (auto it = ep->return_pool.begin(); it != ep->return_pool.end(); ) {
        auto &lc = it->second;
        if (!lc || lc->closed.load() || !lc->conn || lc->conn->is_closed()) {
            it = ep->return_pool.erase(it);
            ++cleaned;
        } else {
            ++it;
        }
    }
    return cleaned;
}

// ============================================================================
// v3.2.1 P1: Direct Return Path MASTER 端 C-API 实现
//（轻量 return slot 管理 + 自动降级 + 入站拦截，与 C++ DirectReturnManager 平行）
// ============================================================================

// stream_token 生成（与 C++ DirectReturnManager::compute_stream_token 一致）
// fnv1a_64(req_id(8B,LE) || timestamp_ms(8B,LE)) 取低 32 位
static std::uint32_t c_compute_stream_token(std::uint64_t req_id, std::uint64_t timestamp_ms) {
    std::uint64_t h = 0xcbf29ce484222325ULL;
    auto mix = [&](std::uint8_t b) { h ^= b; h *= 0x100000001b3ULL; };
    for (int i = 0; i < 8; ++i) mix(static_cast<std::uint8_t>((req_id >> (i * 8)) & 0xFF));
    for (int i = 0; i < 8; ++i) mix(static_cast<std::uint8_t>((timestamp_ms >> (i * 8)) & 0xFF));
    return static_cast<std::uint32_t>(h & 0xFFFFFFFFULL);
}

// 原子取走 return slot（直连/逐跳竞速统一入口）
// 已就绪/取消/不存在时返回 nullptr；同步清理 c_req_id_to_token
// 注意：返回原始指针（非 unique_ptr），因本函数位于 extern "C" 块内，
//       C 链接函数禁止返回 C++ 类类型（MSVC C2526）。调用方负责释放。
static linoh_endpoint::CReturnSlot *c_take_return_slot(
    linoh_endpoint_t *ep, std::uint32_t token) {
    std::lock_guard<std::mutex> lk(ep->return_slots_mu);
    auto it = ep->c_return_slots.find(token);
    if (it == ep->c_return_slots.end()) return nullptr;
    linoh_endpoint::CReturnSlot *raw = it->second.release();
    ep->c_return_slots.erase(it);
    ep->c_req_id_to_token.erase(raw->req_id);
    return raw;
}

// 入站 stream 拦截：尝试解析 ResultPP[DirectReturn] 并路由到 return slot
// 返回 true=已处理（不调用户 on_stream_cb），false=非 DirectReturn（调用户回调）
//
// v3.2.1 P1-2: 状态机式持续读取（与 C++ DirectReturnManager::handle_inbound_stream_ 对齐）
//   - on_stream 仅在 stream 新建时触发一次，此时已到达数据均在 recv_ 中
//   - 循环 parse：支持单 stream 内多条 ApplicationMessage 拼接
//   - 首 message 非 DirectReturn 则交还用户回调（不 consume，保留原始数据）
//   - 跨 UDP 包的大消息由 P3 TensorStream 分片机制处理（每片 < MTU 独立完整）
static bool c_try_handle_direct_return_stream(
    linoh_endpoint_t *ep, std::shared_ptr<endpoint::Stream> s) {
    if (!ep || !ep->direct_return_inbound_enabled) return false;

    // 读取全部可读数据（on_stream 触发时已到达数据均在 recv_ 中）
    auto chunk = s->read(0);
    if (chunk.empty()) return false;

    // 先 peek 首 message 判断是否为 DirectReturn，非 DirectReturn 不 consume（交还用户回调）
    protocol::ApplicationMessage first_msg;
    auto first_n = protocol::ApplicationMessage::parse(
        std::span<const std::uint8_t>(chunk.data(), chunk.size()), first_msg);
    if (first_n <= 0) return false;  // 非 ApplicationMessage 或数据不足
    if (first_msg.method_id != protocol::MethodId::ResultPP ||
        !protocol::has_flag(first_msg.flags, protocol::MessageFlags::DirectReturn)) {
        return false;  // 非 DirectReturn，交给用户回调（不 consume）
    }

    // 确认为 DirectReturn stream，开始循环 parse 消费所有完整消息
    std::size_t consumed = 0;
    std::span<const std::uint8_t> buf(chunk.data(), chunk.size());
    bool any_routed = false;
    for (;;) {
        if (consumed >= buf.size()) break;
        protocol::ApplicationMessage msg;
        auto n = protocol::ApplicationMessage::parse(
            std::span<const std::uint8_t>(buf.data() + consumed, buf.size() - consumed), msg);
        if (n <= 0) break;  // 数据不足，等待更多（但本帧已读完）
        if (msg.method_id == protocol::MethodId::ResultPP &&
            protocol::has_flag(msg.flags, protocol::MessageFlags::DirectReturn)) {
            bool is_shard = protocol::has_flag(
                msg.flags, protocol::MessageFlags::ResultShard);
            if (is_shard && msg.payload.size() >= 8) {
                // P3-1 分片：[stream_token(4B)][shard_idx(2B)][total_shards(2B)][chunk]
                std::uint32_t token =
                    static_cast<std::uint32_t>(msg.payload[0]) |
                    (static_cast<std::uint32_t>(msg.payload[1]) << 8) |
                    (static_cast<std::uint32_t>(msg.payload[2]) << 16) |
                    (static_cast<std::uint32_t>(msg.payload[3]) << 24);
                std::uint16_t shard_idx =
                    static_cast<std::uint16_t>(msg.payload[4]) |
                    (static_cast<std::uint16_t>(msg.payload[5]) << 8);
                std::uint16_t total_shards =
                    static_cast<std::uint16_t>(msg.payload[6]) |
                    (static_cast<std::uint16_t>(msg.payload[7]) << 8);
                std::span<const std::uint8_t> chunk_span(
                    msg.payload.data() + 8, msg.payload.size() - 8);
                // 累积 shard，到齐后 ready
                bool complete = false;
                {
                    std::lock_guard<std::mutex> lk(ep->return_slots_mu);
                    auto it = ep->c_return_slots.find(token);
                    if (it != ep->c_return_slots.end() &&
                        !it->second->ready && !it->second->cancelled) {
                        auto &slot = it->second;
                        if (slot->total_shards == 0) {
                            slot->total_shards = total_shards;
                            slot->shard_chunks.resize(total_shards);
                        }
                        if (shard_idx < slot->total_shards &&
                            slot->shard_chunks[shard_idx].empty()) {
                            slot->shard_chunks[shard_idx].assign(
                                chunk_span.begin(), chunk_span.end());
                            slot->received_shards++;
                        }
                        if (slot->received_shards == slot->total_shards) {
                            // 拼接所有 shard
                            slot->result.clear();
                            for (auto &c : slot->shard_chunks) {
                                slot->result.insert(slot->result.end(),
                                                    c.begin(), c.end());
                            }
                            slot->ready = true;
                            complete = true;
                            ep->return_slots_cv.notify_all();
                        }
                    }
                }
                if (complete) {
                    std::lock_guard<std::mutex> slk(ep->dr_stats_mu);
                    ep->dr_stats.direct_return_won++;
                    ep->dr_stats.results_received++;
                    any_routed = true;
                }
            } else if (msg.payload.size() >= 4) {
                // 非分片：[stream_token(4B)][result_payload]
                std::uint32_t token =
                    static_cast<std::uint32_t>(msg.payload[0]) |
                    (static_cast<std::uint32_t>(msg.payload[1]) << 8) |
                    (static_cast<std::uint32_t>(msg.payload[2]) << 16) |
                    (static_cast<std::uint32_t>(msg.payload[3]) << 24);
                // 路由到 return slot（直连路径竞速）
                {
                    std::lock_guard<std::mutex> lk(ep->return_slots_mu);
                    auto it = ep->c_return_slots.find(token);
                    if (it != ep->c_return_slots.end() &&
                        !it->second->ready && !it->second->cancelled) {
                        it->second->result.assign(
                            msg.payload.begin() + 4, msg.payload.end());
                        it->second->ready = true;
                        ep->return_slots_cv.notify_all();
                    }
                }
                {
                    std::lock_guard<std::mutex> slk(ep->dr_stats_mu);
                    ep->dr_stats.direct_return_won++;
                    ep->dr_stats.results_received++;
                }
                any_routed = true;
            }
        }
        // 非 DirectReturn 消息在此 stream 中忽略（MASTER pp-llm/1 应只收 DirectReturn）
        consumed += static_cast<std::size_t>(n);
    }

    if (consumed > 0) {
        s->consume(consumed);
    }
    // 若首 message 非 DirectReturn 已在前面 return false；此处 any_routed 必为 true
    // 但保留 any_routed 检查以防边界情况（如首消息格式异常被消费）
    return true;
}

int linoh_direct_return_enable_inbound(linoh_endpoint_t *ep) {
    LINOH_C_GUARD_BEGIN
    if (!ep) return LINOH_ERR_PARAM;
    ep->direct_return_inbound_enabled = true;
    LINOH_INFO("linoh_c: direct return inbound interception enabled");
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

uint32_t linoh_register_return_slot(linoh_endpoint_t *ep, uint64_t req_id) {
    LINOH_C_GUARD_BEGIN
    if (!ep) return 0;
    auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    std::uint32_t token = c_compute_stream_token(req_id, now_ms);

    auto slot = std::make_unique<linoh_endpoint::CReturnSlot>();
    slot->req_id = req_id;
    slot->token = token;

    {
        std::lock_guard<std::mutex> lk(ep->return_slots_mu);
        while (ep->c_return_slots.count(token) != 0) {
            now_ms++;
            token = c_compute_stream_token(req_id, now_ms);
        }
        slot->token = token;
        // 防御性：同一 req_id 重复注册时唤醒旧 slot
        auto rit = ep->c_req_id_to_token.find(req_id);
        if (rit != ep->c_req_id_to_token.end()) {
            auto old_it = ep->c_return_slots.find(rit->second);
            if (old_it != ep->c_return_slots.end()) {
                old_it->second->cancelled = true;
                ep->c_return_slots.erase(old_it);
            }
        }
        ep->c_return_slots[token] = std::move(slot);
        ep->c_req_id_to_token[req_id] = token;
    }
    {
        std::lock_guard<std::mutex> slk(ep->dr_stats_mu);
        ep->dr_stats.return_slots_registered++;
    }
    return token;
    LINOH_C_GUARD_END(0)
}

int64_t linoh_await_return_result(linoh_endpoint_t *ep,
                                   uint32_t token,
                                   uint32_t timeout_ms,
                                   uint8_t *out,
                                   size_t out_size) {
    LINOH_C_GUARD_BEGIN
    if (!ep) return -1;

    std::vector<std::uint8_t> result;
    int rc = 0;  // 0=超时/未就绪, 1=就绪, 2=取消/被擦除
    {
        std::unique_lock<std::mutex> lk(ep->return_slots_mu);
        if (ep->c_return_slots.find(token) == ep->c_return_slots.end()) return -1;

        if (timeout_ms == 0) {
            auto it = ep->c_return_slots.find(token);
            if (it->second->ready) {
                std::uint64_t rid = it->second->req_id;
                result.swap(it->second->result);
                ep->c_return_slots.erase(it);
                ep->c_req_id_to_token.erase(rid);
                rc = 1;
            } else if (it->second->cancelled) {
                std::uint64_t rid = it->second->req_id;
                ep->c_return_slots.erase(it);
                ep->c_req_id_to_token.erase(rid);
                rc = 2;
            }
        } else {
            // cv.wait 不持有 iterator：predicate 用 find 重新定位（cancel 会 erase slot）
            ep->return_slots_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                [&] {
                    auto it = ep->c_return_slots.find(token);
                    return it == ep->c_return_slots.end() ||
                           it->second->ready || it->second->cancelled;
                });
            auto it = ep->c_return_slots.find(token);
            if (it == ep->c_return_slots.end()) {
                rc = 2;  // 被 cancel erase
            } else if (it->second->cancelled) {
                std::uint64_t rid = it->second->req_id;
                ep->c_return_slots.erase(it);
                ep->c_req_id_to_token.erase(rid);
                rc = 2;
            } else if (it->second->ready) {
                std::uint64_t rid = it->second->req_id;
                result.swap(it->second->result);
                ep->c_return_slots.erase(it);
                ep->c_req_id_to_token.erase(rid);
                rc = 1;
            }
            // else 超时，slot 仍保留供后续 inject/直连
        }
    }
    if (rc == 2) return -2;
    if (rc == 0) return 0;
    if (out == nullptr) return static_cast<int64_t>(result.size());
    std::size_t n = (std::min)(result.size(), out_size);
    std::memcpy(out, result.data(), n);
    return static_cast<int64_t>(n);
    LINOH_C_GUARD_END(-1)
}

int linoh_inject_hop_by_hop_result(linoh_endpoint_t *ep,
                                    uint64_t req_id,
                                    const uint8_t *payload,
                                    size_t len) {
    LINOH_C_GUARD_BEGIN
    if (!ep) return -1;
    if (len > 0 && !payload) return -1;

    std::uint32_t token = 0;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(ep->return_slots_mu);
        auto it = ep->c_req_id_to_token.find(req_id);
        if (it != ep->c_req_id_to_token.end()) { token = it->second; found = true; }
    }
    {
        std::lock_guard<std::mutex> slk(ep->dr_stats_mu);
        ep->dr_stats.fallback_invoked++;
    }
    if (!found) return 0;  // 直连已胜出或 slot 不存在

    {
        std::lock_guard<std::mutex> lk(ep->return_slots_mu);
        auto it = ep->c_return_slots.find(token);
        if (it == ep->c_return_slots.end()) return 0;  // 直连已取走
        if (it->second->ready || it->second->cancelled) return 0;
        it->second->result.assign(payload, payload + len);
        it->second->ready = true;
        ep->return_slots_cv.notify_all();
    }
    {
        std::lock_guard<std::mutex> slk(ep->dr_stats_mu);
        ep->dr_stats.hop_by_hop_won++;
        ep->dr_stats.results_received++;
    }
    return 1;  // 逐跳反向胜出
    LINOH_C_GUARD_END(-1)
}

void linoh_cancel_return_slot(linoh_endpoint_t *ep, uint32_t token) {
    LINOH_C_GUARD_BEGIN
    if (!ep) return;
    {
        std::lock_guard<std::mutex> lk(ep->return_slots_mu);
        auto it = ep->c_return_slots.find(token);
        if (it == ep->c_return_slots.end()) return;
        std::uint64_t rid = it->second->req_id;
        it->second->cancelled = true;  // 唤醒等待的 await
        ep->c_return_slots.erase(it);
        ep->c_req_id_to_token.erase(rid);
    }
    ep->return_slots_cv.notify_all();
    {
        std::lock_guard<std::mutex> slk(ep->dr_stats_mu);
        ep->dr_stats.return_slots_cancelled++;
    }
    } catch (const std::exception &e) {
        set_error((std::string("linoh_c: exception: ") + e.what()).c_str());
    } catch (...) {
        set_error("linoh_c: unknown exception");
    }
}

int linoh_direct_return_stats(linoh_endpoint_t *ep,
                               linoh_direct_return_stats_t *out) {
    LINOH_C_GUARD_BEGIN
    if (!ep || !out) return LINOH_ERR_PARAM;
    std::lock_guard<std::mutex> lk(ep->dr_stats_mu);
    out->return_streams_opened = ep->dr_stats.return_streams_opened;
    out->return_streams_failed = ep->dr_stats.return_streams_failed;
    out->results_sent_direct = ep->dr_stats.results_sent_direct;
    out->results_received = ep->dr_stats.results_received;
    out->direct_return_won = ep->dr_stats.direct_return_won;
    out->hop_by_hop_won = ep->dr_stats.hop_by_hop_won;
    out->fallback_invoked = ep->dr_stats.fallback_invoked;
    out->return_slots_registered = ep->dr_stats.return_slots_registered;
    out->return_slots_cancelled = ep->dr_stats.return_slots_cancelled;
    out->pool_hits = ep->dr_stats.pool_hits;
    out->pool_misses = ep->dr_stats.pool_misses;
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

int64_t linoh_direct_return_stats_json(linoh_endpoint_t *ep,
                                        char *buf, size_t buf_size) {
    LINOH_C_GUARD_BEGIN
    if (!ep || !buf || buf_size == 0) return LINOH_ERR_PARAM;
    linoh_direct_return_stats_t s;
    // 先用结构体 API 取值（已加锁拷贝）
    if (linoh_direct_return_stats(ep, &s) != LINOH_OK) return LINOH_ERR_INTERNAL;
    // JSON 序列化（与 C++ DirectReturnManager::stats_json 字段一致）
    int n = std::snprintf(buf, buf_size,
        "{"
        "\"return_streams_opened\":%llu,"
        "\"return_streams_failed\":%llu,"
        "\"results_sent_direct\":%llu,"
        "\"results_received\":%llu,"
        "\"direct_return_won\":%llu,"
        "\"hop_by_hop_won\":%llu,"
        "\"fallback_invoked\":%llu,"
        "\"return_slots_registered\":%llu,"
        "\"return_slots_cancelled\":%llu,"
        "\"pool_hits\":%llu,"
        "\"pool_misses\":%llu"
        "}",
        static_cast<unsigned long long>(s.return_streams_opened),
        static_cast<unsigned long long>(s.return_streams_failed),
        static_cast<unsigned long long>(s.results_sent_direct),
        static_cast<unsigned long long>(s.results_received),
        static_cast<unsigned long long>(s.direct_return_won),
        static_cast<unsigned long long>(s.hop_by_hop_won),
        static_cast<unsigned long long>(s.fallback_invoked),
        static_cast<unsigned long long>(s.return_slots_registered),
        static_cast<unsigned long long>(s.return_slots_cancelled),
        static_cast<unsigned long long>(s.pool_hits),
        static_cast<unsigned long long>(s.pool_misses));
    if (n < 0) return LINOH_ERR_INTERNAL;
    // snprintf 返回值可能 >= buf_size（截断），实际写入 = min(n, buf_size-1)
    return static_cast<int64_t>((static_cast<size_t>(n) < buf_size)
                                ? static_cast<size_t>(n)
                                : buf_size - 1);
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}


linoh_connection_t *linoh_endpoint_connect(linoh_endpoint_t *ep,
                                            const char *host, uint16_t port) {
    // v1.5 P1-1: 薄包装到 _with_alpn，向后兼容
    // alpn 传 NULL：内部回退到 ep->alpn，等同旧行为
    return linoh_endpoint_connect_with_alpn(ep, host, port, nullptr);
}

// ============================================================================
// P5-A-1: 多模态双连接 C-API 实现
// ============================================================================

struct linoh_multimodal_conn {
    linoh_connection_t *ctrl{nullptr};   // 控制连接（ALPN=ctrl/1）
    linoh_connection_t *data{nullptr};   // 数据连接（ALPN=pp-*/1）
    linoh_multimodal_channel_t data_channel{LINOH_CHANNEL_LLM_HIDDEN};
};

linoh_multimodal_conn_t *linoh_endpoint_connect_multimodal(
    linoh_endpoint_t *ep,
    const char *host, uint16_t port,
    linoh_multimodal_channel_t data_channel) {
    if (!ep || !host) return nullptr;
    if (data_channel == LINOH_CHANNEL_CONTROL) {
        LINOH_ERROR("linoh_c: data_channel cannot be CONTROL");
        return nullptr;
    }

    // v1.5 P1-1: 改用 _with_alpn，ep->alpn 不再被临时修改（避免旧 swap 副作用与非线程安全）
    // Step 1: 建立控制连接（ALPN=ctrl/1）
    // alpn_for() 返回 std::string_view，显式构造 string 以保证 .c_str() 有 \0 终止
    std::string ctrl_alpn_str(multimodal::alpn_for(multimodal::ChannelType::CONTROL));
    linoh_connection_t *ctrl = linoh_endpoint_connect_with_alpn(
        ep, host, port, ctrl_alpn_str.c_str());
    if (!ctrl) {
        LINOH_ERROR("linoh_c: multimodal ctrl_conn failed");
        return nullptr;
    }

    // Step 2: 建立数据连接（ALPN=pp-*/1）
    auto cpp_channel = static_cast<multimodal::ChannelType>(data_channel);
    // v1.5 P1-1: alpn_for() 返回 std::string_view，无 \0 终止符，
    // 显式构造 std::string 后取 .c_str() 给 _with_alpn（其内部走 const char* → string 构造）
    std::string data_alpn_str(multimodal::alpn_for(cpp_channel));
    linoh_connection_t *data = linoh_endpoint_connect_with_alpn(
        ep, host, port, data_alpn_str.c_str());

    if (!data) {
        // data_conn 失败：清理已建立的 ctrl_conn
        // 注意：ctrl 句柄由 ep->conns 管理，这里不显式释放（由 endpoint_free 统一清理）
        LINOH_ERROR("linoh_c: multimodal data_conn failed");
        return nullptr;
    }

    auto *pair = new linoh_multimodal_conn_t{};
    pair->ctrl = ctrl;
    pair->data = data;
    pair->data_channel = data_channel;

    LINOH_INFO("linoh_c: multimodal conn pair established channel=", data_channel,
               " ctrl+data both connected to ", host, ":", port);
    return pair;
}

linoh_connection_t *linoh_multimodal_ctrl_conn(linoh_multimodal_conn_t *conn_pair) {
    return conn_pair ? conn_pair->ctrl : nullptr;
}

linoh_connection_t *linoh_multimodal_data_conn(linoh_multimodal_conn_t *conn_pair) {
    return conn_pair ? conn_pair->data : nullptr;
}

linoh_multimodal_channel_t linoh_multimodal_data_channel(
    const linoh_multimodal_conn_t *conn_pair) {
    return conn_pair ? conn_pair->data_channel : LINOH_CHANNEL_CONTROL;
}

void linoh_multimodal_conn_free(linoh_multimodal_conn_t *conn_pair) {
    if (!conn_pair) return;
    // 注意：底层 linoh_connection_t 由 endpoint 统一管理（通过 ep->conns map）
    // 这里只清理连接对包装结构
    // 实际连接关闭由 linoh_endpoint_free 或 linoh_connection_close 完成
    delete conn_pair;
}

const char *linoh_channel_alpn(linoh_multimodal_channel_t channel) {
    auto cpp_channel = static_cast<multimodal::ChannelType>(channel);
    // 返回静态字符串映射（避免返回 std::string_view 的 .data() 临时值）
    switch (cpp_channel) {
        case multimodal::ChannelType::CONTROL:       return "ctrl/1";
        case multimodal::ChannelType::LLM_HIDDEN:    return "pp-llm/1";
        case multimodal::ChannelType::IMG_FEATURE:   return "pp-img/1";
        case multimodal::ChannelType::VIDEO_FEATURE: return "pp-video/1";
        case multimodal::ChannelType::AUDIO_FEATURE: return "pp-audio/1";
        case multimodal::ChannelType::FUSION:        return "pp-multi/1";
        case multimodal::ChannelType::EP_DISPATCH:   return "ep-dispatch/1";
        case multimodal::ChannelType::EP_COMBINE:    return "ep-combine/1";
        case multimodal::ChannelType::EP_SYNC:       return "ep-sync/1";
    }
    return "ctrl/1";
}

// ============================================================================
// v1.5.0.2.3: TensorStream C-API 包装（cluster linoh_py 兼容性恢复）
// ============================================================================
//
// 设计要点：
// 1. linoh_tensorstream 是发送端/接收端共用 handle，首次调用 send_shard 或
//    recv_one 时自动确定角色（is_sender 标志）
// 2. 发送端：每 shard 创建一个新 linoh_stream_t，通过 linoh_connection_open_stream
//    + linoh_stream_write 写入 48B TensorMeta 头 + shard data；is_last=1 时
//    finish_send。简单可靠，避免 v1.5.0 fix9P_diag 的"内部 stream pool"复杂性
// 3. 接收端：linoh_connection_accept_stream 拉新 stream，read 48B TensorMeta 头
//    解析，再 read shard data，写入 shards map；is_complete 检查 received_count
//    == total_shards
// 4. 序列化布局（与 linoh::multimodal::TensorMeta 一致，48B 固定头，小端）：
//    [0..7]   tensor_id      u64
//    [8..11]  total_shards   u32
//    [12..15] shard_idx      u32
//    [16]     dtype          u8 (linoh::multimodal::TensorDType)
//    [17..18] reserved       2B
//    [19..34] shape[4]       4×u32
//    [35..42] total_bytes    u64
//    [43..46] shard_bytes    u32
//    [47]     is_last        u8 (0/1)
// 5. 线程安全：所有状态变更加 mu_ 锁；单 tensor 单线程使用为推荐模式
//    （多发送端并发请每个 shard 单独创建 linoh_tensorstream_t）
// 6. timeout 字段语义：仅作"首次 shard 接收时间"参考，超时检测由调用方按需
//    对比 linoh_tensorstream_timeout_ms() 与当前 elapsed，不在内部自动清理

namespace {

// 序列化 TensorMeta 为 48 字节
inline void serialize_tensor_meta(
    uint64_t tensor_id, uint32_t total_shards, uint32_t shard_idx,
    uint8_t dtype, const uint32_t shape[4],
    uint64_t total_bytes, uint32_t shard_bytes, bool is_last,
    uint8_t out[48]) {
    std::memset(out, 0, 48);
    // tensor_id (u64 LE)
    for (int i = 0; i < 8; ++i) out[0 + i] = static_cast<uint8_t>((tensor_id >> (i * 8)) & 0xFF);
    // total_shards (u32 LE)
    for (int i = 0; i < 4; ++i) out[8 + i] = static_cast<uint8_t>((total_shards >> (i * 8)) & 0xFF);
    // shard_idx (u32 LE)
    for (int i = 0; i < 4; ++i) out[12 + i] = static_cast<uint8_t>((shard_idx >> (i * 8)) & 0xFF);
    // dtype (u8)
    out[16] = dtype;
    // reserved [17..18] = 0
    // shape[4] [19..34]
    for (int s = 0; s < 4; ++s) {
        for (int i = 0; i < 4; ++i) {
            out[19 + s * 4 + i] = static_cast<uint8_t>((shape[s] >> (i * 8)) & 0xFF);
        }
    }
    // total_bytes (u64 LE) [35..42]
    for (int i = 0; i < 8; ++i) out[35 + i] = static_cast<uint8_t>((total_bytes >> (i * 8)) & 0xFF);
    // shard_bytes (u32 LE) [43..46]
    for (int i = 0; i < 4; ++i) out[43 + i] = static_cast<uint8_t>((shard_bytes >> (i * 8)) & 0xFF);
    // is_last (u8) [47]
    out[47] = is_last ? 1 : 0;
}

// 反序列化 48 字节 TensorMeta，返回是否成功
inline bool parse_tensor_meta(const uint8_t in[48],
                               uint64_t &tensor_id, uint32_t &total_shards, uint32_t &shard_idx,
                               uint8_t &dtype, uint32_t shape[4],
                               uint64_t &total_bytes, uint32_t &shard_bytes, bool &is_last) {
    // tensor_id
    tensor_id = 0;
    for (int i = 0; i < 8; ++i) tensor_id |= static_cast<uint64_t>(in[0 + i]) << (i * 8);
    // total_shards
    total_shards = 0;
    for (int i = 0; i < 4; ++i) total_shards |= static_cast<uint32_t>(in[8 + i]) << (i * 8);
    // shard_idx
    shard_idx = 0;
    for (int i = 0; i < 4; ++i) shard_idx |= static_cast<uint32_t>(in[12 + i]) << (i * 8);
    // dtype
    dtype = in[16];
    // shape
    for (int s = 0; s < 4; ++s) {
        shape[s] = 0;
        for (int i = 0; i < 4; ++i) {
            shape[s] |= static_cast<uint32_t>(in[19 + s * 4 + i]) << (i * 8);
        }
    }
    // total_bytes
    total_bytes = 0;
    for (int i = 0; i < 8; ++i) total_bytes |= static_cast<uint64_t>(in[35 + i]) << (i * 8);
    // shard_bytes
    shard_bytes = 0;
    for (int i = 0; i < 4; ++i) shard_bytes |= static_cast<uint32_t>(in[43 + i]) << (i * 8);
    // is_last
    is_last = in[47] != 0;
    return true;
}

}  // anonymous namespace

// C-API 内部结构：发送端/接收端共用
struct linoh_tensorstream {
    linoh_connection_t *conn{nullptr};
    uint64_t tensor_id{0};
    uint32_t total_shards{0};
    uint32_t timeout_ms{300000};
    linoh_multimodal_channel_t channel_type{LINOH_CHANNEL_VIDEO_FEATURE};

    // 角色
    bool is_sender{false};   // true=发送端（调过 send_shard），false=接收端
    bool is_receiver{false}; // true=接收端（调过 recv_one）

    // 发送端计数
    uint32_t sent_count{0};

    // 接收端重组
    std::map<uint32_t, std::vector<uint8_t>> shards;
    uint32_t received_count{0};     // 已收到的不同 shard_idx 数（去重后）
    uint64_t total_bytes{0};         // 由 first meta 推断
    uint32_t first_meta_shard_bytes{0}; // 单 shard 大小（由 first meta 推断）
    bool first_received{false};
    std::chrono::steady_clock::time_point first_seen_time;

    std::mutex mu;
};

linoh_tensorstream_t *linoh_tensorstream_create(
    linoh_connection_t *conn,
    const linoh_tensorstream_config_t *config) {
    if (!conn) { set_error("null conn"); return nullptr; }
    auto *ts = new linoh_tensorstream_t{};
    ts->conn = conn;
    if (config) {
        ts->tensor_id = config->tensor_id;
        ts->total_shards = config->total_shards;
        ts->timeout_ms = config->timeout_ms ? config->timeout_ms : 300000u;
        ts->channel_type = config->channel_type;
    } else {
        ts->timeout_ms = 300000u;
    }
    LINOH_INFO("linoh_c: tensorstream_create conn=", (void*)conn,
               " tensor_id=", (unsigned long long)ts->tensor_id,
               " total_shards=", ts->total_shards,
               " timeout_ms=", ts->timeout_ms,
               " channel=", (int)ts->channel_type);
    return ts;
}

void linoh_tensorstream_free(linoh_tensorstream_t *ts) {
    if (!ts) return;
    delete ts;
}

// 发送一个分片：每 shard 创建一个新 stream，写入 48B TensorMeta 头 + shard data
// 成功返回写入字节数（48 + data_len），失败返回 0
size_t linoh_tensorstream_send_shard(
    linoh_tensorstream_t *ts,
    uint32_t shard_idx,
    const uint8_t *data,
    size_t data_len,
    int is_last) {
    if (!ts || !ts->conn || !data) {
        set_error("null ts/conn/data");
        return 0;
    }
    std::lock_guard<std::mutex> lk(ts->mu);
    ts->is_sender = true;

    // 若 total_shards==0，由 send_shard 调用次数推断（首次调用时设）
    if (ts->total_shards == 0) {
        // 推断：调用方将多次 send_shard，最后一次 is_last=1。
        // total_shards 暂存为 shard_idx+1（保守估计），后续收到更大 idx 不再改。
        // 推荐用法：create 时显式给 total_shards
        ts->total_shards = shard_idx + 1;
    }

    // 1) 创建新 stream
    linoh_stream_t *stream = linoh_connection_open_stream(ts->conn);
    if (!stream) {
        set_error("open_stream failed");
        return 0;
    }

    // 2) 若 tensor_id == 0，用随机数分配（每分片独立 tensor 时）
    if (ts->tensor_id == 0) {
        linoh_error_t rc = linoh_random_bytes(
            reinterpret_cast<uint8_t*>(&ts->tensor_id), sizeof(ts->tensor_id));
        if (rc != LINOH_OK) {
            set_error("tensor_id random failed");
            linoh_stream_free(stream);
            return 0;
        }
        // 避免 0
        if (ts->tensor_id == 0) ts->tensor_id = 1;
    }

    // 3) 构造并写入 48B TensorMeta 头
    uint8_t header[48];
    // dtype/shape 暂用 0（linoh_py 当前未传 dtype/shape；后续如需可在 config 中加字段）
    uint32_t shape[4] = {0, 0, 0, 0};
    uint8_t dtype = 0; // F32 占位
    uint64_t total_bytes = static_cast<uint64_t>(data_len) * ts->total_shards;  // 估算
    serialize_tensor_meta(
        ts->tensor_id, ts->total_shards, shard_idx,
        dtype, shape,
        total_bytes, static_cast<uint32_t>(data_len), is_last != 0,
        header);

    size_t hdr_written = linoh_stream_write(stream, header, 48);
    if (hdr_written != 48) {
        set_error("write header short");
        linoh_stream_free(stream);
        return 0;
    }

    // 4) 写入 shard data
    size_t data_written = 0;
    if (data_len > 0) {
        data_written = linoh_stream_write(stream, data, data_len);
        if (data_written != data_len) {
            set_error("write data short");
            linoh_stream_free(stream);
            return 0;
        }
    }

    // 5) 若是最后一片，标记本端 FIN；否则立刻释放 stream（让 STREAM 帧立即发出）
    if (is_last) {
        linoh_stream_finish(stream);
    }
    linoh_stream_free(stream);

    ts->sent_count++;
    LINOH_DEBUG("linoh_c: tensorstream_send_shard tensor_id=",
                (unsigned long long)ts->tensor_id,
                " shard_idx=", shard_idx,
                " data_len=", data_len,
                " is_last=", is_last,
                " sent_count=", ts->sent_count);
    return 48 + data_len;
}

// 接收一个分片（pull 模式，非阻塞）
// 返回值：
//   1 = 收到一个分片（写入内部 shards map）
//   0 = 当前无新分片可接收（调用方应继续轮询或检查超时）
//  -1 = 错误
int linoh_tensorstream_recv_one(linoh_tensorstream_t *ts) {
    if (!ts || !ts->conn) {
        set_error("null ts/conn");
        return -1;
    }
    std::lock_guard<std::mutex> lk(ts->mu);
    ts->is_receiver = true;

    // 1) 接受一个新 stream
    linoh_stream_t *stream = linoh_connection_accept_stream(ts->conn);
    if (!stream) {
        return 0;  // 无新 stream，非阻塞
    }

    // 2) 读取 48B TensorMeta 头
    uint8_t header[48];
    size_t hdr_total = 0;
    while (hdr_total < 48) {
        size_t n = linoh_stream_read(stream, header + hdr_total, 48 - hdr_total);
        if (n == 0) {
            // 对端 FIN 或无数据
            if (linoh_stream_fin_received(stream)) {
                set_error("recv_one: stream FIN before header complete");
                linoh_stream_free(stream);
                return -1;
            }
            // 非阻塞：暂时无数据，释放 stream 句柄让下次重试
            // 注意：accept_stream 已移走 stream 所有权，linoh_stream_free 是安全的
            linoh_stream_free(stream);
            return 0;
        }
        hdr_total += n;
    }

    // 3) 解析头部
    uint64_t tensor_id;
    uint32_t total_shards, shard_idx, shard_bytes;
    uint8_t dtype;
    uint32_t shape[4];
    uint64_t total_bytes;
    bool is_last;
    parse_tensor_meta(header, tensor_id, total_shards, shard_idx,
                      dtype, shape, total_bytes, shard_bytes, is_last);

    // 4) 用对端告知的 tensor_id/total_shards 覆盖本地（首次到达为准）
    if (!ts->first_received) {
        ts->tensor_id = tensor_id;
        ts->total_shards = total_shards;
        ts->total_bytes = total_bytes;
        ts->first_meta_shard_bytes = shard_bytes;
        ts->first_seen_time = std::chrono::steady_clock::now();
        ts->first_received = true;
    }

    // 5) 读取 shard data
    std::vector<uint8_t> shard_data(shard_bytes);
    size_t data_total = 0;
    while (data_total < shard_bytes) {
        size_t n = linoh_stream_read(stream, shard_data.data() + data_total, shard_bytes - data_total);
        if (n == 0) {
            if (linoh_stream_fin_received(stream)) {
                set_error("recv_one: stream FIN before data complete");
                linoh_stream_free(stream);
                return -1;
            }
            // 非阻塞：暂时无数据
            linoh_stream_free(stream);
            return 0;
        }
        data_total += n;
    }

    // 6) 写入 shards map（去重）
    auto [it, inserted] = ts->shards.try_emplace(shard_idx, std::move(shard_data));
    if (inserted) {
        ts->received_count++;
    }
    LINOH_DEBUG("linoh_c: tensorstream_recv_one tensor_id=",
                (unsigned long long)tensor_id,
                " shard_idx=", shard_idx,
                " data_len=", data_total,
                " is_last=", is_last,
                " received_count=", ts->received_count);
    linoh_stream_free(stream);
    return 1;
}

int linoh_tensorstream_is_complete(linoh_tensorstream_t *ts) {
    if (!ts) return 0;
    std::lock_guard<std::mutex> lk(ts->mu);
    if (ts->total_shards == 0) return 0;
    return ts->received_count >= ts->total_shards ? 1 : 0;
}

size_t linoh_tensorstream_received_count(linoh_tensorstream_t *ts) {
    if (!ts) return 0;
    std::lock_guard<std::mutex> lk(ts->mu);
    return ts->received_count;
}

size_t linoh_tensorstream_total_size(linoh_tensorstream_t *ts) {
    if (!ts) return 0;
    std::lock_guard<std::mutex> lk(ts->mu);
    if (ts->total_bytes > 0) return static_cast<size_t>(ts->total_bytes);
    // 估算：received shards * first shard size
    if (ts->first_meta_shard_bytes > 0) {
        return static_cast<size_t>(ts->first_meta_shard_bytes) * ts->total_shards;
    }
    return 0;
}

size_t linoh_tensorstream_copy_to(
    linoh_tensorstream_t *ts,
    uint8_t *buf,
    size_t buf_size) {
    if (!ts || !buf) return 0;
    std::lock_guard<std::mutex> lk(ts->mu);
    // 按 shard_idx 顺序拼接
    size_t written = 0;
    for (auto &kv : ts->shards) {
        size_t remaining = buf_size - written;
        if (remaining == 0) break;
        size_t to_copy = (std::min)(kv.second.size(), remaining);
        std::memcpy(buf + written, kv.second.data(), to_copy);
        written += to_copy;
    }
    return written;
}

uint64_t linoh_tensorstream_tensor_id(linoh_tensorstream_t *ts) {
    if (!ts) return 0;
    std::lock_guard<std::mutex> lk(ts->mu);
    return ts->tensor_id;
}

uint32_t linoh_tensorstream_timeout_ms(linoh_tensorstream_t *ts) {
    if (!ts) return 0;
    std::lock_guard<std::mutex> lk(ts->mu);
    return ts->timeout_ms;
}

// ============================================================================
// v1.6.0.1 (P0+): EP（Expert Parallelism）C-API 实现
// ============================================================================
//
// 包装 C++ EpChannelAdapter / EpSession / EpWorkerSession。
// shim 层：C 函数指针 + user_data ↔ std::function，捕获 linoh_ep_channel* this。

// --- EP channel 不透明结构实现 ---
struct linoh_ep_channel {
    std::unique_ptr<multimodal::ep::EpChannelAdapter> adapter;
    linoh_endpoint_t *endpoint{nullptr};   // 反向引用（不持有），用于 create 时快照默认回调
    bool transferred{false};                // 是否已转移所有权给 session

    // C 回调 + user_data（channel 级覆盖）
    linoh_ep_on_dispatch_fn      on_dispatch{nullptr};
    void                        *dispatch_ud{nullptr};
    linoh_ep_on_combine_fn       on_combine{nullptr};
    void                        *combine_ud{nullptr};
    linoh_ep_on_sync_fn          on_sync{nullptr};
    void                        *sync_ud{nullptr};
    linoh_ep_on_frame_dropped_fn on_dropped{nullptr};
    void                        *dropped_ud{nullptr};
};

// 内部：把 C 回调包装成 EpChannelCallbacks 并 set_callbacks
// 捕获 ch 指针；ch 析构前必须保证 adapter 不再持有这些 lambda（free/transfer 时清空）
static void apply_ep_channel_callbacks_(linoh_ep_channel *ch) {
    if (!ch || !ch->adapter) return;
    multimodal::ep::EpChannelCallbacks cbs;
    if (ch->on_dispatch) {
        cbs.on_dispatch_received = [ch](const multimodal::ep::EpDispatchFrame &f) {
            const uint8_t *pad = f.padding.empty() ? nullptr : f.padding.data();
            ch->on_dispatch(ch, f.tensor_id, f.expert_id, f.token_cnt,
                            f.payload.data(), f.payload.size(),
                            pad, f.padding.size(),
                            ch->dispatch_ud);
        };
    }
    if (ch->on_combine) {
        cbs.on_combine_received = [ch](const multimodal::ep::EpCombineFrame &f) {
            ch->on_combine(ch, f.tensor_id, f.expert_id, f.token_cnt,
                           f.payload.data(), f.payload.size(),
                           ch->combine_ud);
        };
    }
    if (ch->on_sync) {
        cbs.on_sync_received = [ch](const multimodal::ep::EpSyncFrame &f) {
            ch->on_sync(ch, f.sync_id, static_cast<int>(f.sync_op),
                        f.participant_mask, f.reduce_op,
                        f.payload.data(), f.payload.size(),
                        ch->sync_ud);
        };
    }
    if (ch->on_dropped) {
        cbs.on_frame_dropped = [ch](multimodal::ep::EpFrameType type,
                                     std::uint64_t frame_seq, std::uint64_t tensor_id) {
            ch->on_dropped(ch, static_cast<int>(type), frame_seq, tensor_id,
                           ch->dropped_ud);
        };
    }
    ch->adapter->set_callbacks(std::move(cbs));
}

linoh_ep_channel_t *linoh_ep_channel_create(linoh_connection_t *data_conn) {
    if (!data_conn || !data_conn->conn) {
        set_error("ep_channel_create: data_conn invalid");
        return nullptr;
    }
    auto adapter = std::make_unique<multimodal::ep::EpChannelAdapter>(data_conn->conn);
    auto *ch = new linoh_ep_channel_t{};
    ch->adapter = std::move(adapter);
    ch->endpoint = data_conn->endpoint;

    // 快照 endpoint 默认回调（继承语义）
    if (ch->endpoint) {
        std::lock_guard<std::mutex> lk(ch->endpoint->mu);
        ch->on_dispatch = ch->endpoint->ep_on_dispatch;
        ch->dispatch_ud = ch->endpoint->ep_dispatch_ud;
        ch->on_combine = ch->endpoint->ep_on_combine;
        ch->combine_ud = ch->endpoint->ep_combine_ud;
        ch->on_sync = ch->endpoint->ep_on_sync;
        ch->sync_ud = ch->endpoint->ep_sync_ud;
        ch->on_dropped = ch->endpoint->ep_on_dropped;
        ch->dropped_ud = ch->endpoint->ep_dropped_ud;
    }
    apply_ep_channel_callbacks_(ch);
    LINOH_INFO("linoh_c: ep_channel created from conn=", (void*)data_conn);
    return ch;
}

void linoh_ep_channel_free(linoh_ep_channel_t *ch) {
    if (!ch) return;
    if (!ch->transferred && ch->adapter) {
        // 未转移：停止循环并释放 adapter
        ch->adapter->stop_recv_loop();
        ch->adapter->stop_resend_loop();
        // 清空回调避免 lambda 在析构链中引用 ch
        ch->adapter->set_callbacks({});
    }
    // transferred=true：adapter 已归 session，只释放 ch 壳
    delete ch;
}

int linoh_ep_channel_start(linoh_ep_channel_t *ch) {
    if (!ch || !ch->adapter) return LINOH_ERR_PARAM;
    ch->adapter->start_recv_loop();
    ch->adapter->start_resend_loop();
    return LINOH_OK;
}

void linoh_ep_channel_stop(linoh_ep_channel_t *ch) {
    if (!ch || !ch->adapter) return;
    ch->adapter->stop_recv_loop();
    ch->adapter->stop_resend_loop();
}

int linoh_ep_channel_is_running(const linoh_ep_channel_t *ch) {
    if (!ch || !ch->adapter) return 0;
    // EpChannelIf 无 is_running，用 adapter 底层 channel_ptr 查询
    auto *raw = ch->adapter->channel_ptr();
    return (raw && raw->is_recv_running()) ? 1 : 0;
}

int linoh_ep_channel_send_dispatch(linoh_ep_channel_t *ch,
                                   uint64_t tensor_id, uint64_t expert_id,
                                   uint64_t token_cnt,
                                   const uint8_t *payload, size_t payload_len,
                                   const uint8_t *padding, size_t padding_len) {
    if (!ch || !ch->adapter) return LINOH_ERR_PARAM;
    if (payload_len > 0 && !payload) return LINOH_ERR_PARAM;
    std::span<const uint8_t> p(payload, payload_len);
    std::span<const uint8_t> pad(padding, padding_len);
    bool ok = ch->adapter->send_dispatch(tensor_id, expert_id, token_cnt, p, pad);
    if (!ok) { set_error("ep_send_dispatch failed"); return LINOH_ERR_INTERNAL; }
    return LINOH_OK;
}

int linoh_ep_channel_send_combine(linoh_ep_channel_t *ch,
                                  uint64_t tensor_id, uint64_t expert_id,
                                  uint64_t token_cnt,
                                  const uint8_t *payload, size_t payload_len) {
    if (!ch || !ch->adapter) return LINOH_ERR_PARAM;
    if (payload_len > 0 && !payload) return LINOH_ERR_PARAM;
    std::span<const uint8_t> p(payload, payload_len);
    bool ok = ch->adapter->send_combine(tensor_id, expert_id, token_cnt, p);
    if (!ok) { set_error("ep_send_combine failed"); return LINOH_ERR_INTERNAL; }
    return LINOH_OK;
}

int linoh_ep_channel_send_sync(linoh_ep_channel_t *ch,
                               uint64_t sync_id, int sync_op,
                               uint64_t participant_mask,
                               uint8_t reduce_op,
                               const uint8_t *payload, size_t payload_len) {
    if (!ch || !ch->adapter) return LINOH_ERR_PARAM;
    if (payload_len > 0 && !payload) return LINOH_ERR_PARAM;
    if (sync_op < 0 || sync_op > 4) return LINOH_ERR_PARAM;
    std::span<const uint8_t> p(payload, payload_len);
    // EpChannelIf::send_sync 默认 reduce_op=0（接口未暴露 reduce_op 参数，用底层 channel_ptr）
    auto *raw = ch->adapter->channel_ptr();
    if (!raw) { set_error("ep_send_sync: no raw channel"); return LINOH_ERR_INTERNAL; }
    bool ok = raw->send_sync(sync_id,
                             static_cast<multimodal::ep::EpSyncOp>(sync_op),
                             participant_mask, p, reduce_op);
    if (!ok) { set_error("ep_send_sync failed"); return LINOH_ERR_INTERNAL; }
    return LINOH_OK;
}

void linoh_ep_channel_on_dispatch(linoh_ep_channel_t *ch,
                                  linoh_ep_on_dispatch_fn cb, void *user_data) {
    if (!ch) return;
    ch->on_dispatch = cb;
    ch->dispatch_ud = user_data;
    apply_ep_channel_callbacks_(ch);
}

void linoh_ep_channel_on_combine(linoh_ep_channel_t *ch,
                                 linoh_ep_on_combine_fn cb, void *user_data) {
    if (!ch) return;
    ch->on_combine = cb;
    ch->combine_ud = user_data;
    apply_ep_channel_callbacks_(ch);
}

void linoh_ep_channel_on_sync(linoh_ep_channel_t *ch,
                              linoh_ep_on_sync_fn cb, void *user_data) {
    if (!ch) return;
    ch->on_sync = cb;
    ch->sync_ud = user_data;
    apply_ep_channel_callbacks_(ch);
}

void linoh_ep_channel_on_frame_dropped(linoh_ep_channel_t *ch,
                                       linoh_ep_on_frame_dropped_fn cb, void *user_data) {
    if (!ch) return;
    ch->on_dropped = cb;
    ch->dropped_ud = user_data;
    apply_ep_channel_callbacks_(ch);
}

int linoh_ep_channel_stats(const linoh_ep_channel_t *ch,
                           uint64_t *dispatch_sent, uint64_t *combine_sent,
                           uint64_t *sync_sent, uint64_t *dispatch_recv,
                           uint64_t *combine_recv, uint64_t *sync_recv,
                           uint64_t *dispatch_resent, uint64_t *combine_resent,
                           uint64_t *ack_sent, uint64_t *ack_recv) {
    if (!ch || !ch->adapter) return LINOH_ERR_PARAM;
    auto s = ch->adapter->stats();
    if (dispatch_sent)   *dispatch_sent   = s.dispatch_sent;
    if (combine_sent)    *combine_sent    = s.combine_sent;
    if (sync_sent)       *sync_sent       = s.sync_sent;
    if (dispatch_recv)   *dispatch_recv   = s.dispatch_recv;
    if (combine_recv)    *combine_recv    = s.combine_recv;
    if (sync_recv)       *sync_recv       = s.sync_recv;
    if (dispatch_resent) *dispatch_resent = s.dispatch_resent;
    if (combine_resent)  *combine_resent  = s.combine_resent;
    if (ack_sent)        *ack_sent        = s.ack_sent;
    if (ack_recv)        *ack_recv        = s.ack_recv;
    return LINOH_OK;
}

// ============================================================================
// endpoint 级 EP 默认回调注册
// ============================================================================

void linoh_endpoint_on_ep_dispatch(linoh_endpoint_t *ep,
                                   linoh_ep_on_dispatch_fn cb, void *user_data) {
    if (!ep) return;
    std::lock_guard<std::mutex> lk(ep->mu);
    ep->ep_on_dispatch = cb;
    ep->ep_dispatch_ud = user_data;
}

void linoh_endpoint_on_ep_combine(linoh_endpoint_t *ep,
                                  linoh_ep_on_combine_fn cb, void *user_data) {
    if (!ep) return;
    std::lock_guard<std::mutex> lk(ep->mu);
    ep->ep_on_combine = cb;
    ep->ep_combine_ud = user_data;
}

void linoh_endpoint_on_ep_sync(linoh_endpoint_t *ep,
                               linoh_ep_on_sync_fn cb, void *user_data) {
    if (!ep) return;
    std::lock_guard<std::mutex> lk(ep->mu);
    ep->ep_on_sync = cb;
    ep->ep_sync_ud = user_data;
}

void linoh_endpoint_on_ep_frame_dropped(linoh_endpoint_t *ep,
                                        linoh_ep_on_frame_dropped_fn cb, void *user_data) {
    if (!ep) return;
    std::lock_guard<std::mutex> lk(ep->mu);
    ep->ep_on_dropped = cb;
    ep->ep_dropped_ud = user_data;
}

// ============================================================================
// EP 字节缓冲释放
// ============================================================================

void linoh_ep_bytes_free(linoh_ep_bytes_t *combines, size_t cnt) {
    if (!combines) return;
    for (size_t i = 0; i < cnt; ++i) {
        if (combines[i].data) std::free(combines[i].data);
    }
    std::free(combines);
}

void linoh_ep_compute_result_free(linoh_ep_bytes_t *r) {
    if (!r) return;
    if (r->data) std::free(r->data);
    r->data = nullptr;
    r->len = 0;
}

// ============================================================================
// EP Session（master 端）实现
// ============================================================================

struct linoh_ep_session {
    // 配置快照（dispatch 时构造 EpGroupConfig）
    std::uint64_t master_node_id{0};
    std::uint32_t num_experts{0};
    std::uint32_t topk{1};
    int dtype{0};
    std::uint32_t max_tokens{0};
    std::uint32_t hidden_dim{0};
    std::uint32_t expert_count{1};

    // worker 拓扑（按 add_worker 顺序）
    std::vector<std::uint64_t> worker_ids;
    std::vector<std::vector<std::uint32_t>> expert_placement;

    // dispatch 临时状态（EpSession 回调写入，dispatch 返回后读取）
    // v1.6.0.2 fix: 这些成员必须在 sess 之前声明、之后析构。
    //   注册到 EpSession 的回调 lambda 捕获 this（linoh_ep_session*），
    //   访问 dispatch_mu / last_combines / all_received。
    //   ~linoh_ep_session() 按声明逆序析构：sess 最先析构（触发 ~EpSession，
    //   其间 channel join 可能执行回调），此时下方三个成员仍存活 → 安全。
    //   反之若 sess 声明在首位（最后析构），回调访问已析构成员 → UAF/heap corruption。
    std::mutex dispatch_mu;
    std::vector<std::vector<std::uint8_t>> last_combines;
    bool all_received{false};

    // sess 最后声明 → 最先析构 → 析构时上方成员均存活
    std::unique_ptr<multimodal::ep::EpSession> sess;
};

linoh_ep_session_t *linoh_ep_session_create(const linoh_ep_session_config_t *cfg) {
    if (!cfg) { set_error("ep_session_create: cfg null"); return nullptr; }
    auto *s = new linoh_ep_session_t{};
    s->master_node_id = cfg->master_node_id;
    s->num_experts = cfg->num_experts;
    s->topk = cfg->topk > 0 ? cfg->topk : 1;
    s->dtype = cfg->dtype;
    s->max_tokens = cfg->max_tokens;
    s->hidden_dim = cfg->hidden_dim;
    s->expert_count = cfg->expert_count > 0 ? cfg->expert_count : 1;

    s->sess = std::make_unique<multimodal::ep::EpSession>(s->master_node_id);
    s->sess->set_allow_partial_combine(cfg->allow_partial_combine != 0);

    // 注册回调：收齐 combine 时存入 last_combines
    multimodal::ep::EpSessionCallbacks cbs;
    cbs.on_all_combine_received = [s](const multimodal::ep::EpCommPlan &,
                                       const std::vector<std::vector<std::uint8_t>> &combines) {
        std::lock_guard<std::mutex> lk(s->dispatch_mu);
        s->last_combines = combines;
        s->all_received = true;
    };
    cbs.on_partial_combine = [s](const multimodal::ep::EpCommPlan &,
                                  std::uint64_t, std::uint64_t,
                                  const std::vector<std::vector<std::uint8_t>> &combines) {
        std::lock_guard<std::mutex> lk(s->dispatch_mu);
        s->last_combines = combines;
        s->all_received = false;
    };
    s->sess->set_callbacks(std::move(cbs));
    LINOH_INFO("linoh_c: ep_session created master=", s->master_node_id);
    return s;
}

void linoh_ep_session_free(linoh_ep_session_t *sess) {
    if (!sess) return;
    // v1.6.0.2 fix: 先清空 EpSession 回调，切断 lambda 对 this（linoh_ep_session*）的引用，
    //   再 delete。防御纵深：即使 ~EpSession() 析构链中 channel join 触发回调，
    //   回调已被清空（空 std::function），不会访问已析构的 dispatch_mu/last_combines。
    //   与 linoh_ep_channel_free 的 set_callbacks({}) 模式一致。
    //   安全性：set_callbacks 内部加 cb_mu_，此时 EpSession 完整存活，锁可用。
    sess->sess->set_callbacks({});
    // EpSession 析构会 stop 所有 worker channel 循环并释放 channel（unique_ptr<EpChannelIf>）
    delete sess;
}

int linoh_ep_session_add_worker(linoh_ep_session_t *sess,
                                uint64_t worker_node_id,
                                linoh_ep_channel_t *ch,
                                const uint32_t *expert_ids, size_t expert_cnt) {
    if (!sess || !ch || !ch->adapter) return LINOH_ERR_PARAM;
    if (expert_cnt > 0 && !expert_ids) return LINOH_ERR_PARAM;

    // 清空 channel 应用回调（避免 lambda 悬空引用 ch）
    ch->adapter->set_callbacks({});
    // 转移 adapter 所有权给 EpSession
    std::unique_ptr<multimodal::ep::EpChannelIf> if_ptr(ch->adapter.release());
    ch->transferred = true;

    bool ok = sess->sess->connect_worker(worker_node_id, std::move(if_ptr));
    if (!ok) {
        set_error("ep_session_add_worker: duplicate or failed");
        return LINOH_ERR_INTERNAL;
    }
    sess->worker_ids.push_back(worker_node_id);
    sess->expert_placement.emplace_back(expert_ids, expert_ids + expert_cnt);
    return LINOH_OK;
}

int linoh_ep_session_remove_worker(linoh_ep_session_t *sess, uint64_t worker_node_id) {
    if (!sess) return LINOH_ERR_PARAM;
    bool ok = sess->sess->disconnect_worker(worker_node_id);
    if (!ok) { set_error("ep_session_remove_worker: not found"); return LINOH_ERR_INTERNAL; }
    // 同步本地拓扑
    auto it = std::find(sess->worker_ids.begin(), sess->worker_ids.end(), worker_node_id);
    if (it != sess->worker_ids.end()) {
        auto idx = std::distance(sess->worker_ids.begin(), it);
        sess->worker_ids.erase(it);
        if (static_cast<size_t>(idx) < sess->expert_placement.size()) {
            sess->expert_placement.erase(sess->expert_placement.begin() + idx);
        }
    }
    return LINOH_OK;
}

size_t linoh_ep_session_worker_count(const linoh_ep_session_t *sess) {
    return sess ? sess->sess->worker_count() : 0;
}

int linoh_ep_session_dispatch(linoh_ep_session_t *sess,
                              const uint32_t *routing, size_t token_cnt,
                              size_t expert_cnt_per_token,
                              const uint8_t *payload, size_t payload_len,
                              uint64_t timeout_ms,
                              linoh_ep_bytes_t **combines_out,
                              size_t *combines_cnt_out) {
    if (!sess || !routing || token_cnt == 0) return LINOH_ERR_PARAM;
    if (expert_cnt_per_token == 0) return LINOH_ERR_PARAM;
    if (payload_len > 0 && !payload) return LINOH_ERR_PARAM;
    if (!combines_out || !combines_cnt_out) return LINOH_ERR_PARAM;

    // 1. 一维 routing → vector<vector<uint32_t>>
    std::vector<std::vector<std::uint32_t>> routing_vec;
    routing_vec.reserve(token_cnt);
    for (size_t i = 0; i < token_cnt; ++i) {
        const uint32_t *base = routing + i * expert_cnt_per_token;
        routing_vec.emplace_back(base, base + expert_cnt_per_token);
    }

    // 2. 构造 EpGroupConfig
    multimodal::ep::EpGroupConfig cfg;
    cfg.ep_master = sess->master_node_id;
    cfg.ep_workers = sess->worker_ids;
    cfg.expert_placement = sess->expert_placement;
    cfg.num_experts = sess->num_experts;
    cfg.topk = sess->topk;
    cfg.shape.dtype = static_cast<multimodal::TensorDType>(sess->dtype);
    cfg.shape.max_tokens = sess->max_tokens;
    cfg.shape.hidden_dim = sess->hidden_dim;
    cfg.shape.expert_count = sess->expert_count;

    // 3. 重置 dispatch 临时状态
    {
        std::lock_guard<std::mutex> lk(sess->dispatch_mu);
        sess->last_combines.clear();
        sess->all_received = false;
    }

    // 4. 调用 EpSession::dispatch（阻塞）
    std::span<const uint8_t> p(payload, payload_len);
    auto timeout = timeout_ms > 0
        ? std::chrono::milliseconds(timeout_ms)
        : std::chrono::seconds(30);
    auto plan = sess->sess->dispatch(routing_vec, cfg, p, timeout);

    if (plan.total_tokens == 0) {
        set_error("ep_session_dispatch: plan failed (total_tokens=0)");
        return LINOH_ERR_INTERNAL;
    }

    // 5. 取出 combines
    std::vector<std::vector<std::uint8_t>> combines;
    bool all;
    {
        std::lock_guard<std::mutex> lk(sess->dispatch_mu);
        combines = std::move(sess->last_combines);
        all = sess->all_received;
    }

    // 6. 转 C 数组
    linoh_ep_bytes_t *out = (linoh_ep_bytes_t*)std::calloc(combines.size(), sizeof(linoh_ep_bytes_t));
    if (!out && !combines.empty()) {
        set_error("ep_session_dispatch: calloc failed");
        return LINOH_ERR_INTERNAL;
    }
    for (size_t i = 0; i < combines.size(); ++i) {
        out[i].len = combines[i].size();
        if (combines[i].empty()) {
            out[i].data = nullptr;
        } else {
            out[i].data = (uint8_t*)std::malloc(combines[i].size());
            if (!out[i].data) {
                // 分配失败：回滚已分配的
                for (size_t j = 0; j < i; ++j) std::free(out[j].data);
                std::free(out);
                set_error("ep_session_dispatch: malloc failed");
                return LINOH_ERR_INTERNAL;
            }
            std::memcpy(out[i].data, combines[i].data(), combines[i].size());
        }
    }
    *combines_out = out;
    *combines_cnt_out = combines.size();

    if (!all) {
        set_error("ep_session_dispatch: combine timeout or partial");
        return LINOH_ERR_INTERNAL;
    }
    return LINOH_OK;
}

// ============================================================================
// EP Worker Session 实现
// ============================================================================

struct linoh_ep_worker_session {
    // v1.6.0.2 fix: w 最后声明 → 最先析构。
    //   compute 回调 lambda 捕获 this（linoh_ep_worker_session*），访问 compute_cb/compute_ud。
    //   w 先析构（触发 ~EpWorkerSession，其间可能执行 compute 回调）时，
    //   compute_cb/compute_ud 仍存活 → 安全。
    linoh_ep_compute_fn compute_cb{nullptr};
    void *compute_ud{nullptr};
    std::unique_ptr<multimodal::ep::EpWorkerSession> w;
};

linoh_ep_worker_session_t *linoh_ep_worker_session_create(uint64_t worker_node_id) {
    auto *ws = new linoh_ep_worker_session_t{};
    ws->w = std::make_unique<multimodal::ep::EpWorkerSession>(worker_node_id);
    LINOH_INFO("linoh_c: ep_worker_session created worker=", worker_node_id);
    return ws;
}

void linoh_ep_worker_session_free(linoh_ep_worker_session_t *w) {
    if (!w) return;
    // v1.6.0.2 fix: 先清空 compute 回调，切断 lambda 对 this 的引用，再 delete。
    //   防御纵深：~EpWorkerSession() 析构链中若触发 compute 回调，已被清空不执行。
    if (w->w) w->w->set_compute_callback(nullptr);
    // EpWorkerSession 析构会 stop 并释放 channel（unique_ptr<EpChannelIf>）
    delete w;
}

int linoh_ep_worker_session_set_channel(linoh_ep_worker_session_t *w,
                                        linoh_ep_channel_t *ch) {
    if (!w || !ch || !ch->adapter) return LINOH_ERR_PARAM;
    // 清空 channel 应用回调（避免 lambda 悬空）
    ch->adapter->set_callbacks({});
    std::unique_ptr<multimodal::ep::EpChannelIf> if_ptr(ch->adapter.release());
    ch->transferred = true;
    w->w->set_channel(std::move(if_ptr));
    return LINOH_OK;
}

int linoh_ep_worker_session_set_compute(linoh_ep_worker_session_t *w,
                                        linoh_ep_compute_fn cb, void *user_data) {
    if (!w || !cb) return LINOH_ERR_PARAM;
    w->compute_cb = cb;
    w->compute_ud = user_data;
    // 包装成 EpWorkerSession::ComputeCallback
    w->w->set_compute_callback([w](std::uint64_t tid, std::uint64_t eid,
                                    std::uint64_t tcnt,
                                    std::span<const std::uint8_t> payload) {
        auto res = w->compute_cb(tid, eid, tcnt, payload.data(), payload.size(), w->compute_ud);
        std::vector<std::uint8_t> vec(res.data ? res.data : nullptr,
                                       res.data ? res.data + res.len : nullptr);
        // 释放 C 回调返回的 bytes（约定 .data 由 malloc 分配）
        linoh_ep_compute_result_free(&res);
        return vec;
    });
    return LINOH_OK;
}

int linoh_ep_worker_session_start(linoh_ep_worker_session_t *w) {
    if (!w || !w->w) return LINOH_ERR_PARAM;
    w->w->start();
    return LINOH_OK;
}

void linoh_ep_worker_session_stop(linoh_ep_worker_session_t *w) {
    if (!w || !w->w) return;
    w->w->stop();
}

int linoh_ep_worker_session_is_running(const linoh_ep_worker_session_t *w) {
    return (w && w->w && w->w->is_running()) ? 1 : 0;
}

// ============================================================================
// V3-A: 跨域节点视图 C-API 实现
//
// 包装 C++ ControlPlane 的跨域查询能力，供 orchestrator / 外部调度器使用。
// C 句柄 linoh_control_plane_t 非拥有底层 C++ 对象（仅持有裸指针）。
// ============================================================================

struct linoh_control_plane {
    ControlPlane *cp;  // 非拥有指针，生命周期由调用方管理
};

linoh_control_plane_t *linoh_control_plane_from_cpp(void *cpp_control_plane) {
    if (!cpp_control_plane) {
        set_error("linoh_control_plane_from_cpp: null cpp_control_plane");
        return nullptr;
    }
    auto *handle = new (std::nothrow) linoh_control_plane_t;
    if (!handle) {
        set_error("linoh_control_plane_from_cpp: out of memory");
        return nullptr;
    }
    handle->cp = static_cast<ControlPlane *>(cpp_control_plane);
    return handle;
}

void linoh_control_plane_free(linoh_control_plane_t *cp) {
    // 仅释放 C 包装层，不释放底层 C++ ControlPlane 对象
    delete cp;
}

int linoh_get_cross_domain_nodes(
    linoh_control_plane_t *cp,
    linoh_cross_domain_node_view_t *out_views,
    int max_count) {
    if (!cp || !cp->cp) {
        set_error("linoh_get_cross_domain_nodes: null control plane handle");
        return 0;
    }
    if (max_count <= 0 || !out_views) {
        set_error("linoh_get_cross_domain_nodes: invalid out_views or max_count");
        return 0;
    }

    // 调用 C++ API 获取跨域节点视图（已按 overall_score 降序）
    auto entries = cp->cp->get_cross_domain_view();
    int filled = 0;
    for (const auto &entry : entries) {
        if (filled >= max_count) break;
        auto &view = out_views[filled];
        view.domain_id = entry.domain_id;
        // EndpointId (base::PublicKey) → linoh_endpoint_id_t (32 bytes)
        auto id_span = entry.profile.endpoint_id.as_span();
        std::memset(view.endpoint.bytes, 0, LINOH_KEY_SIZE);
        std::memcpy(view.endpoint.bytes, id_span.data(),
                    std::min<size_t>(id_span.size(), LINOH_KEY_SIZE));
        view.overall_score = entry.sort_score();
        view.region = static_cast<uint8_t>(entry.profile.geo.region);
        view.state = static_cast<uint8_t>(entry.state);
        view.is_cross_domain_rep = entry.is_cross_domain_rep ? 1 : 0;
        std::memset(view.reserved, 0, sizeof(view.reserved));
        ++filled;
    }
    return filled;
}

int linoh_get_cross_domain_node_count(linoh_control_plane_t *cp) {
    if (!cp || !cp->cp) {
        return 0;
    }
    // 复用 get_cross_domain_view 获取数量（跨域未启用时返回空 vector）
    return static_cast<int>(cp->cp->get_cross_domain_view().size());
}

int linoh_is_cross_domain_rep(linoh_control_plane_t *cp) {
    if (!cp || !cp->cp) {
        return 0;
    }
    return cp->cp->is_cross_domain_rep() ? 1 : 0;
}

// ============================================================================
// V3-B: 跨域数据面通道 C-API 实现
//
// 包装 C++ ControlPlane / Connection / RelayPool / CongestionController 的跨域能力。
// 跨域连接建立流程：地址解析 → connect_with_alpn → set_cross_domain 标记。
// ============================================================================

int linoh_control_plane_set_relay_pool(linoh_control_plane_t *cp, void *relay_pool) {
    if (!cp || !cp->cp) {
        set_error("linoh_control_plane_set_relay_pool: null control plane handle");
        return -1;
    }
    if (!relay_pool) {
        set_error("linoh_control_plane_set_relay_pool: null relay_pool");
        return -1;
    }
    cp->cp->set_relay_pool(static_cast<nat::RelayPool *>(relay_pool));
    return 0;
}

int linoh_set_cross_domain_backbone_relays(
    linoh_control_plane_t *cp,
    const char *const *relay_urls,
    int count) {
    if (!cp || !cp->cp) {
        set_error("linoh_set_cross_domain_backbone_relays: null control plane handle");
        return -1;
    }
    if (count <= 0 || !relay_urls) {
        set_error("linoh_set_cross_domain_backbone_relays: invalid count or relay_urls");
        return -1;
    }

    auto *pool = cp->cp->relay_pool();
    if (!pool) {
        set_error("linoh_set_cross_domain_backbone_relays: RelayPool not injected "
                  "(call linoh_control_plane_set_relay_pool first)");
        return -2;
    }

    // 转换 C 字符串数组为 std::vector<base::RelayUrl>
    std::vector<base::RelayUrl> urls;
    urls.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        if (!relay_urls[i] || !relay_urls[i][0]) {
            set_error("linoh_set_cross_domain_backbone_relays: empty relay url at index");
            return -1;
        }
        urls.emplace_back(std::string(relay_urls[i]));
    }

    pool->set_cross_domain_backbone_relays(urls);
    LINOH_INFO("linoh_c: set_cross_domain_backbone_relays, count=", count);
    return 0;
}

int linoh_connect_cross_domain(
    linoh_endpoint_t *endpoint,
    linoh_control_plane_t *cp,
    const linoh_endpoint_id_t *peer_endpoint,
    uint32_t peer_domain_id,
    const char *alpn,
    linoh_connection_t **out_conn) {
    if (!endpoint || !cp || !cp->cp || !peer_endpoint || !alpn || !out_conn) {
        set_error("linoh_connect_cross_domain: invalid argument (null parameter)");
        return -1;
    }
    *out_conn = nullptr;

    // 1. 构造 base::EndpointId（从 linoh_endpoint_id_t 32 字节）
    base::PublicKey peer_key;
    std::memcpy(peer_key.data(), peer_endpoint->bytes, LINOH_KEY_SIZE);

    // 2. 跨域地址解析（机制 A: AddrHint 缓存 → B: Pkarr DNS → C: 兜底）
    auto addr_opt = cp->cp->registry().resolve_cross_domain_addr(peer_key, nullptr);
    if (!addr_opt.has_value()) {
        set_error("linoh_connect_cross_domain: resolve_cross_domain_addr failed "
                  "(no AddrHint cache, no Pkarr DNS result)");
        return -2;
    }

    // 3. 从 EndpointAddr 提取第一个 IP 直连地址
    const auto &direct_addrs = addr_opt->direct_addresses();
    std::string host;
    uint16_t port = 0;
    bool found_ip = false;
    for (const auto &ta : direct_addrs) {
        if (ta.kind == base::TransportKind::Ip && !ta.host.empty() && ta.port > 0) {
            host = ta.host;
            port = ta.port;
            found_ip = true;
            break;
        }
    }
    if (!found_ip) {
        // 仅有 Relay 地址，C-API 暂不支持 Relay 兜底连接（需 C++ Endpoint 的 NAT 穿透）
        set_error("linoh_connect_cross_domain: no direct IP address resolved "
                  "(relay-only endpoint, use C++ Endpoint for NAT traversal)");
        return -2;
    }

    // 4. 调用既有 connect_with_alpn 建立 ALPN 数据连接
    linoh_connection_t *lc = linoh_endpoint_connect_with_alpn(endpoint,
                                                               host.c_str(), port, alpn);
    if (!lc || !lc->conn) {
        set_error("linoh_connect_cross_domain: connect_with_alpn failed");
        return -3;
    }

    // 5. 标记连接为跨域数据面连接（运行时设置，数据传输前调用）
    lc->conn->set_cross_domain(true, peer_domain_id);

    // 6. 协商跨域 MTU（保守 1500，不启用 jumbo）
    //    注：linoh C-API 的 Connection 不直接持有 NetReport，使用默认保守参数
    auto mtu_result = net::MtuNegotiator::negotiate_cross_domain(
        net::MtuConstants::kStandardMtu,  // 本端期望 1500
        net::MtuConstants::kStandardMtu,  // 对端期望 1500
        net::NatType::Unknown,            // 未知 NAT 类型，保守处理
        net::UdpFirewall::Open,
        false /* force_jumbo */);
    LINOH_INFO("linoh_c: cross-domain MTU negotiated=", mtu_result.negotiated_mtu,
               " reason=", mtu_result.reason);

    *out_conn = lc;
    LINOH_INFO("linoh_c: cross-domain connection established, peer_domain=", peer_domain_id,
               " host=", host, " port=", port, " alpn=", alpn);
    return 0;
}

int linoh_get_cross_domain_conn_stats(
    linoh_connection_t *conn,
    linoh_cross_domain_stats_t *out_stats) {
    if (!conn || !conn->conn || !out_stats) {
        set_error("linoh_get_cross_domain_conn_stats: invalid argument (null parameter)");
        return -1;
    }

    if (!conn->conn->is_cross_domain()) {
        set_error("linoh_get_cross_domain_conn_stats: connection is not cross-domain");
        return -1;
    }

    auto stats = conn->conn->cross_domain_stats();
    out_stats->bytes_sent_cross_domain = stats.bytes_sent_cross_domain;
    out_stats->bytes_received_cross_domain = stats.bytes_received_cross_domain;
    out_stats->rtt_ms = stats.rtt_ms;
    out_stats->peer_domain_id = stats.peer_domain_id;
    return 0;
}

int linoh_apply_cross_domain_bbr_config(
    linoh_connection_t *conn,
    const linoh_cross_domain_bbr_config_t *config) {
    if (!conn || !conn->conn || !config) {
        set_error("linoh_apply_cross_domain_bbr_config: invalid argument (null parameter)");
        return -1;
    }

    // 获取连接的拥塞控制器（Connection 内部持有）
    // 注：linoh Connection 通过 congestion_controller() 暴露指针
    auto *controller = conn->conn->congestion_controller();
    if (!controller) {
        set_error("linoh_apply_cross_domain_bbr_config: no congestion controller");
        return -2;
    }

    // 构造 C++ BbrCrossDomainConfig
    protocol::BbrCrossDomainConfig cfg;
    cfg.cross_domain_min_rtt_window =
        std::chrono::seconds(config->cross_domain_min_rtt_window_sec);
    cfg.cross_domain_probe_rtt_interval =
        std::chrono::seconds(config->cross_domain_probe_rtt_interval_sec);
    cfg.cross_domain_startup_gain = config->cross_domain_startup_gain;
    cfg.cross_domain_cwnd_gain = config->cross_domain_cwnd_gain;
    cfg.cross_domain_enable_pacing = (config->cross_domain_enable_pacing != 0);

    if (!controller->apply_cross_domain_config(cfg)) {
        set_error("linoh_apply_cross_domain_bbr_config: controller does not support "
                  "cross-domain adaptation (NewReno returns false)");
        return -2;
    }

    // 同时标记连接为跨域（若尚未标记），确保跨域统计累积
    if (!conn->conn->is_cross_domain()) {
        conn->conn->set_cross_domain(true, 0);
    }

    LINOH_INFO("linoh_c: applied cross-domain BBR config, "
               "min_rtt_window=", config->cross_domain_min_rtt_window_sec, "s",
               " probe_rtt_interval=", config->cross_domain_probe_rtt_interval_sec, "s",
               " cwnd_gain=", config->cross_domain_cwnd_gain);
    return 0;
}

// ============================================================================
// V3.5 P5-B SessionId C-API 实现
//
// 对应 C++ linoh::protocol::SessionId。薄封装，转发到 C++ 实现。
// ============================================================================

linoh_error_t linoh_session_id_generate(linoh_session_id_t *out) {
    LINOH_C_GUARD_BEGIN
    if (!out) return LINOH_ERR_PARAM;
    auto sid = protocol::SessionId::generate();
    std::memcpy(out->bytes, sid.bytes.data(), protocol::SessionId::kSize);
    return sid.is_null() ? LINOH_ERR_CRYPTO : LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_session_id_from_bytes(const uint8_t *data, size_t len,
                                           linoh_session_id_t *out) {
    LINOH_C_GUARD_BEGIN
    if (!data || !out || len < protocol::SessionId::kSize) return LINOH_ERR_PARAM;
    auto sid_opt = protocol::SessionId::parse(
        std::span<const uint8_t>(data, len));
    if (!sid_opt) return LINOH_ERR_PARAM;
    std::memcpy(out->bytes, sid_opt->bytes.data(), protocol::SessionId::kSize);
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

size_t linoh_session_id_to_bytes(const linoh_session_id_t *sid,
                                  uint8_t *out, size_t out_cap) {
    LINOH_C_GUARD_BEGIN
    if (!sid || !out || out_cap < protocol::SessionId::kSize) return 0;
    std::memcpy(out, sid->bytes, protocol::SessionId::kSize);
    return protocol::SessionId::kSize;
    LINOH_C_GUARD_END(0)
}

size_t linoh_session_id_to_string(const linoh_session_id_t *sid,
                                    char *buf, size_t buf_size) {
    LINOH_C_GUARD_BEGIN
    if (!sid || !buf || buf_size < 37) return 0;
    protocol::SessionId cpp_sid;
    std::memcpy(cpp_sid.bytes.data(), sid->bytes, protocol::SessionId::kSize);
    auto s = cpp_sid.to_string();
    if (s.size() + 1 > buf_size) return 0;
    std::snprintf(buf, buf_size, "%s", s.c_str());
    return s.size() + 1;
    LINOH_C_GUARD_END(0)
}

int linoh_session_id_is_null(const linoh_session_id_t *sid) {
    LINOH_C_GUARD_BEGIN
    if (!sid) return -1;
    for (std::size_t i = 0; i < protocol::SessionId::kSize; ++i) {
        if (sid->bytes[i] != 0) return 0;
    }
    return 1;
    LINOH_C_GUARD_END(-1)
}

int linoh_session_id_equal(const linoh_session_id_t *a,
                            const linoh_session_id_t *b) {
    LINOH_C_GUARD_BEGIN
    if (!a || !b) return -1;
    return std::memcmp(a->bytes, b->bytes, protocol::SessionId::kSize) == 0 ? 1 : 0;
    LINOH_C_GUARD_END(-1)
}

// ============================================================================
// V3.5 P5-B Compression C-API 实现
//
// 对应 C++ linoh::protocol::compress_payload / decompress_payload /
// recommend_compression。薄封装。
// ============================================================================

linoh_error_t linoh_compress_payload(const uint8_t *in, size_t in_len,
                                       int algo, int level,
                                       uint8_t *out, size_t out_cap,
                                       size_t *out_len) {
    LINOH_C_GUARD_BEGIN
    if (in_len == 0) {
        if (out_len) *out_len = 0;
        return LINOH_OK;
    }
    if (!in || !out || !out_len) return LINOH_ERR_PARAM;

    auto cpp_algo = static_cast<protocol::CompressionAlgo>(algo);
    if (cpp_algo == protocol::CompressionAlgo::Gzip) {
        // Gzip V3.5 暂未实现
        return LINOH_ERR_PARAM;
    }

    auto compressed = protocol::compress_payload(
        std::span<const uint8_t>(in, in_len), cpp_algo, level);
    if (compressed.empty()) {
        // None 算法对非空输入应返回原样，empty 表示内部错误
        if (cpp_algo == protocol::CompressionAlgo::None) {
            return LINOH_ERR_INTERNAL;
        }
        return LINOH_ERR_INTERNAL;
    }
    if (compressed.size() > out_cap) {
        return LINOH_ERR_INTERNAL;  // 缓冲区不足
    }

    std::memcpy(out, compressed.data(), compressed.size());
    *out_len = compressed.size();
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_decompress_payload(const uint8_t *in, size_t in_len,
                                         int algo, size_t expected_size,
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_len) {
    LINOH_C_GUARD_BEGIN
    if (!in || !in_len || !out || !out_len) return LINOH_ERR_PARAM;

    auto cpp_algo = static_cast<protocol::CompressionAlgo>(algo);
    if (cpp_algo == protocol::CompressionAlgo::Gzip) {
        return LINOH_ERR_PARAM;  // Gzip 暂未实现
    }

    auto decompressed = protocol::decompress_payload(
        std::span<const uint8_t>(in, in_len), cpp_algo, expected_size);
    if (decompressed.empty()) {
        // None 算法对非空输入应返回原样，empty 表示内部错误或解压失败
        return LINOH_ERR_INTERNAL;
    }
    if (decompressed.size() > out_cap) {
        return LINOH_ERR_INTERNAL;  // 缓冲区不足
    }

    std::memcpy(out, decompressed.data(), decompressed.size());
    *out_len = decompressed.size();
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_recommend_compression(size_t payload_size, int method_id,
                                            int *out_algo) {
    LINOH_C_GUARD_BEGIN
    if (!out_algo) return LINOH_ERR_PARAM;
    auto method = static_cast<protocol::MethodId>(method_id);
    auto algo = protocol::recommend_compression(payload_size, method);
    *out_algo = static_cast<int>(algo);
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

// ============================================================================
// O1: 协议字典压缩（cluster 编码层优化方案）
// ============================================================================

linoh_error_t linoh_load_protocol_dict(uint8_t dict_id, const uint8_t *dict,
                                        size_t len) {
    LINOH_C_GUARD_BEGIN
    if (!dict || len == 0) return LINOH_ERR_PARAM;
    if (!protocol::load_protocol_dict(dict_id,
            std::span<const std::uint8_t>(dict, len))) {
        return LINOH_ERR_PARAM;
    }
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_set_auto_compress(int enable, int level) {
    LINOH_C_GUARD_BEGIN
    protocol::set_auto_compress(enable != 0, level);
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

// O3
linoh_error_t linoh_load_protocol_dict_file(const char *path, uint8_t dict_id) {
    LINOH_C_GUARD_BEGIN
    if (!path) return LINOH_ERR_PARAM;
    if (!protocol::load_protocol_dict_file(path, dict_id)) return LINOH_ERR_PARAM;
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_protocol_dict_info(uint8_t dict_id, uint64_t *out_size,
                                        uint64_t *out_xxh64) {
    LINOH_C_GUARD_BEGIN
    auto info = protocol::protocol_dict_info(dict_id);
    if (!info.loaded) return LINOH_ERR_PARAM;
    if (out_size) *out_size = info.size;
    if (out_xxh64) *out_xxh64 = info.xxh64;
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

// ============================================================================
// O3: FEC 自适应控制器（C API，不透明句柄包装）
// ============================================================================

linoh_error_t linoh_fec_adaptive_create(void **out_handle) {
    LINOH_C_GUARD_BEGIN
    if (!out_handle) return LINOH_ERR_PARAM;
    *out_handle = new fec::FecAdaptiveController();
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_fec_adaptive_update(void *handle, uint64_t sent_total,
                                         uint64_t lost_total, int *out_switched) {
    LINOH_C_GUARD_BEGIN
    if (!handle) return LINOH_ERR_PARAM;
    auto *c = static_cast<fec::FecAdaptiveController *>(handle);
    bool switched = c->update(sent_total, lost_total);
    if (out_switched) *out_switched = switched ? 1 : 0;
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_fec_adaptive_current(void *handle, int *out_recovery_blocks,
                                          double *out_loss_rate) {
    LINOH_C_GUARD_BEGIN
    if (!handle || !out_recovery_blocks) return LINOH_ERR_PARAM;
    auto *c = static_cast<fec::FecAdaptiveController *>(handle);
    *out_recovery_blocks = c->current_recovery_blocks();
    if (out_loss_rate) *out_loss_rate = c->loss_rate_ema();
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

linoh_error_t linoh_fec_adaptive_destroy(void *handle) {
    LINOH_C_GUARD_BEGIN
    if (!handle) return LINOH_ERR_PARAM;
    delete static_cast<fec::FecAdaptiveController *>(handle);
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

// ============================================================================
// v4.3.0 M7: 事件循环 select! 多路复用（C-API 实现）
//
// 不透明句柄实现：struct 定义对 C 不可见，C 仅持有指针。
//
// 设计要点：
//   1. linoh_event_loop 包装 event::EventLoop（栈内成员，零额外分配）
//   2. linoh_event_source 持有 unique_ptr<EventSource> + kind 标签，
//      通过 as_shutdown()/as_linoh()/as_timer() 静态转型调用子类方法
//      （避免 dynamic_cast 开销，kind 由工厂函数设置，外部不可篡改）
//   3. EventLoop 用 register_source_ref 引用注册（不转移所有权），
//      source 生命周期由 linoh_event_source 管理（C 调用方控制 destroy 时机）
//   4. EventLoop 析构时自动解绑 source 的 loop_ 指针，
//      因此"先 destroy loop 再 destroy source"也安全（source 析构时 loop_ 已 nullptr）
// ============================================================================

/// linoh_event_loop_t 的实际实现（全局命名空间，匹配 linoh_c.h 前向声明）
struct linoh_event_loop {
    event::EventLoop loop;
};

/// linoh_event_source_t 的实际实现
struct linoh_event_source {
    /// 持有具体事件源对象（unique_ptr 自动管理生命周期，virtual 析构安全）
    std::unique_ptr<event::EventSource> base;

    /// 类型标签（工厂函数设置，用于操作函数 dispatch）
    enum class Kind : std::uint8_t {
        Shutdown = 0,
        Linoh    = 1,
        Timer    = 2,
    } kind;

    /// 安全转型（kind 匹配才返回有效指针，否则 nullptr）
    event::ShutdownEvent* as_shutdown() noexcept {
        return kind == Kind::Shutdown
                   ? static_cast<event::ShutdownEvent*>(base.get())
                   : nullptr;
    }
    event::LinohEventSource* as_linoh() noexcept {
        return kind == Kind::Linoh
                   ? static_cast<event::LinohEventSource*>(base.get())
                   : nullptr;
    }
    event::TimerEvent* as_timer() noexcept {
        return kind == Kind::Timer
                   ? static_cast<event::TimerEvent*>(base.get())
                   : nullptr;
    }
};

// === EventLoop C-API ===

linoh_event_loop_t *linoh_event_loop_create(void) {
    LINOH_C_GUARD_BEGIN
    return new (std::nothrow) linoh_event_loop;
    LINOH_C_GUARD_END(nullptr)
}

void linoh_event_loop_destroy(linoh_event_loop_t *loop) {
    LINOH_C_GUARD_BEGIN
    // EventLoop 析构会解绑所有 source 的 loop_ 指针（见 event_loop.cpp ~EventLoop）
    // source 本身由 linoh_event_source 持有，不受影响
    delete static_cast<linoh_event_loop*>(loop);
    return;
    LINOH_C_GUARD_END_VOID()
}

int linoh_event_loop_register(linoh_event_loop_t *loop,
                                linoh_event_source_t *src, int priority) {
    LINOH_C_GUARD_BEGIN
    if (!loop || !src) {
        set_error("linoh_event_loop_register: null argument");
        return -1;
    }
    auto *lp = static_cast<linoh_event_loop*>(loop);
    auto *sp = static_cast<linoh_event_source*>(src);
    if (!sp->base) {
        set_error("linoh_event_loop_register: source base is null");
        return -1;
    }
    // 用 register_source_ref 引用注册：不转移所有权
    // source 生命周期由 linoh_event_source 管理（C 调用方控制 destroy）
    std::size_t idx = lp->loop.register_source_ref(*sp->base, priority);
    // size_t 可能 > INT_MAX（理论），实际 source 数量有限，强制转 int 安全
    if (idx > static_cast<std::size_t>(0x7FFFFFFF)) {
        set_error("linoh_event_loop_register: too many sources");
        return -1;
    }
    return static_cast<int>(idx);
    LINOH_C_GUARD_END(-1)
}

int linoh_event_loop_select(linoh_event_loop_t *loop, int *out_ids,
                              int max_ids, int timeout_ms) {
    LINOH_C_GUARD_BEGIN
    if (!loop) {
        set_error("linoh_event_loop_select: null loop");
        return -1;
    }
    if (max_ids > 0 && !out_ids) {
        set_error("linoh_event_loop_select: null out_ids");
        return -1;
    }
    if (max_ids < 0) max_ids = 0;

    auto *lp = static_cast<linoh_event_loop*>(loop);
    // timeout_ms 语义：>0=等待毫秒数，0=非阻塞，<0=永久阻塞
    std::chrono::milliseconds timeout(timeout_ms);
    std::vector<std::size_t> ready = lp->loop.select(timeout);

    // 拷贝到 out_ids（截断到 max_ids，多出的 ready source 不上报但仍是 ready 状态）
    // 注意：被截断的 source 不会因 select 返回而 clear_ready，下次 select 仍会立即返回
    //       调用方应保证 max_ids 足够大（典型 8-16）
    int n = 0;
    for (std::size_t i = 0; i < ready.size() && n < max_ids; ++i) {
        std::size_t idx = ready[i];
        if (idx > static_cast<std::size_t>(0x7FFFFFFF)) continue;  // 防御
        out_ids[n++] = static_cast<int>(idx);
    }
    return n;
    LINOH_C_GUARD_END(-1)
}

// === EventSource 工厂函数 ===

linoh_event_source_t *linoh_shutdown_event_create(void) {
    LINOH_C_GUARD_BEGIN
    auto *p = new (std::nothrow) linoh_event_source;
    if (!p) return nullptr;
    p->base = std::make_unique<event::ShutdownEvent>();
    p->kind = linoh_event_source::Kind::Shutdown;
    return reinterpret_cast<linoh_event_source_t*>(p);
    LINOH_C_GUARD_END(nullptr)
}

linoh_event_source_t *linoh_linoh_event_create(linoh_endpoint_t *ep,
                                                  linoh_event_mode_t mode) {
    LINOH_C_GUARD_BEGIN
    if (!ep) {
        set_error("linoh_linoh_event_create: null endpoint");
        return nullptr;
    }
    auto *p = new (std::nothrow) linoh_event_source;
    if (!p) return nullptr;
    auto cpp_mode = (mode == LINOH_EVENT_MODE_SELF)
                        ? event::LinohEventSource::Mode::SelfDriven
                        : event::LinohEventSource::Mode::ExternalDriven;
    p->base = std::make_unique<event::LinohEventSource>(ep, cpp_mode);
    p->kind = linoh_event_source::Kind::Linoh;
    return reinterpret_cast<linoh_event_source_t*>(p);
    LINOH_C_GUARD_END(nullptr)
}

linoh_event_source_t *linoh_timer_event_create(uint32_t period_ms) {
    LINOH_C_GUARD_BEGIN
    auto *p = new (std::nothrow) linoh_event_source;
    if (!p) return nullptr;
    p->base = std::make_unique<event::TimerEvent>(
        std::chrono::milliseconds(period_ms));
    p->kind = linoh_event_source::Kind::Timer;
    return reinterpret_cast<linoh_event_source_t*>(p);
    LINOH_C_GUARD_END(nullptr)
}

// === EventSource 操作函数（按 kind dispatch） ===

int linoh_shutdown_event_trigger(linoh_event_source_t *src) {
    LINOH_C_GUARD_BEGIN
    if (!src) {
        set_error("linoh_shutdown_event_trigger: null source");
        return -1;
    }
    auto *sp = static_cast<linoh_event_source*>(src);
    auto *sd = sp->as_shutdown();
    if (!sd) {
        set_error("linoh_shutdown_event_trigger: source is not ShutdownEvent");
        return -1;
    }
    sd->trigger();
    return 0;
    LINOH_C_GUARD_END(-1)
}

int linoh_linoh_event_drive(linoh_event_source_t *src) {
    LINOH_C_GUARD_BEGIN
    if (!src) {
        set_error("linoh_linoh_event_drive: null source");
        return -1;
    }
    auto *sp = static_cast<linoh_event_source*>(src);
    auto *net = sp->as_linoh();
    if (!net) {
        set_error("linoh_linoh_event_drive: source is not LinohEventSource");
        return -1;
    }
    return net->drive();  // 返回事件数（>=0）
    LINOH_C_GUARD_END(-1)
}

int linoh_linoh_event_start(linoh_event_source_t *src) {
    LINOH_C_GUARD_BEGIN
    if (!src) {
        set_error("linoh_linoh_event_start: null source");
        return -1;
    }
    auto *sp = static_cast<linoh_event_source*>(src);
    auto *net = sp->as_linoh();
    if (!net) {
        set_error("linoh_linoh_event_start: source is not LinohEventSource");
        return -1;
    }
    net->start();
    return 0;
    LINOH_C_GUARD_END(-1)
}

int linoh_linoh_event_stop(linoh_event_source_t *src) {
    LINOH_C_GUARD_BEGIN
    if (!src) {
        set_error("linoh_linoh_event_stop: null source");
        return -1;
    }
    auto *sp = static_cast<linoh_event_source*>(src);
    auto *net = sp->as_linoh();
    if (!net) {
        set_error("linoh_linoh_event_stop: source is not LinohEventSource");
        return -1;
    }
    net->stop();
    return 0;
    LINOH_C_GUARD_END(-1)
}

int linoh_timer_event_reset(linoh_event_source_t *src) {
    LINOH_C_GUARD_BEGIN
    if (!src) {
        set_error("linoh_timer_event_reset: null source");
        return -1;
    }
    auto *sp = static_cast<linoh_event_source*>(src);
    auto *tm = sp->as_timer();
    if (!tm) {
        set_error("linoh_timer_event_reset: source is not TimerEvent");
        return -1;
    }
    tm->reset();
    return 0;
    LINOH_C_GUARD_END(-1)
}

void linoh_event_source_destroy(linoh_event_source_t *src) {
    LINOH_C_GUARD_BEGIN
    if (!src) return;
    auto *sp = static_cast<linoh_event_source*>(src);
    // 先从已注册的 EventLoop 注销，避免 EventLoop 后续 select/析构访问已释放的 source
    // （use-after-free 根因修复 v4.3.0 M7）
    if (sp->base) {
        event::EventLoop *loop = sp->base->registered_loop();
        if (loop) {
            loop->unregister_source(*sp->base);
        }
        // unique_ptr 析构 delete base（virtual 析构安全）
    }
    delete sp;
    return;
    LINOH_C_GUARD_END_VOID()
}

// ============================================================================
// v5.1.0 T-LA: Tensor 分片流水线 C-API 实现
//
// 包装 linoh::multimodal::TensorStreamer / TensorReassembler，供 LLMPP
// node-agent 接入分片流水线（附录 A 计算通信重叠优化）。
//
// 设计要点：
//   - struct 壳持有 C++ 对象 + C 回调函数指针 + user_data
//   - 回调用 lambda 桥接，捕获 struct 指针（析构前清空防 UAF）
//   - shard / tensor data 跨 FFI 边界用 malloc/free（C ABI 兼容）
//   - 所有函数体用 LINOH_C_GUARD 包裹（C++ 异常不穿越语言边界）
// ============================================================================

struct linoh_tensor_streamer {
    multimodal::TensorStreamer streamer;
    explicit linoh_tensor_streamer(std::size_t shard_size, std::size_t parallel_streams)
        : streamer(shard_size, parallel_streams) {}
};

struct linoh_tensor_reassembler {
    multimodal::TensorReassembler reassembler;
    linoh_on_tensor_complete_fn        complete_cb{nullptr};
    void                              *complete_ud{nullptr};
    linoh_on_tensor_merkle_failure_fn  merkle_cb{nullptr};
    void                              *merkle_ud{nullptr};
    linoh_on_tensor_chunk_failure_fn   chunk_cb{nullptr};
    void                              *chunk_ud{nullptr};
};

linoh_tensor_streamer_t *linoh_tensor_streamer_create(size_t shard_size,
                                                       size_t parallel_streams) {
    LINOH_C_GUARD_BEGIN
    return new linoh_tensor_streamer(shard_size, parallel_streams);
    LINOH_C_GUARD_END(nullptr)
}

void linoh_tensor_streamer_free(linoh_tensor_streamer_t *s) {
    LINOH_C_GUARD_BEGIN
    if (!s) return;
    delete s;
    return;
    LINOH_C_GUARD_END_VOID()
}

size_t linoh_tensor_streamer_shard_size(const linoh_tensor_streamer_t *s) {
    LINOH_C_GUARD_BEGIN
    if (!s) return 0;
    return s->streamer.shard_size();
    LINOH_C_GUARD_END(0)
}

size_t linoh_tensor_streamer_parallel_streams(const linoh_tensor_streamer_t *s) {
    LINOH_C_GUARD_BEGIN
    if (!s) return 0;
    return s->streamer.parallel_streams();
    LINOH_C_GUARD_END(0)
}

size_t linoh_tensor_streamer_shard_count(const linoh_tensor_streamer_t *s,
                                          size_t total_bytes) {
    LINOH_C_GUARD_BEGIN
    if (!s) return 0;
    return s->streamer.shard_count(total_bytes);
    LINOH_C_GUARD_END(0)
}

int linoh_tensor_streamer_shard(linoh_tensor_streamer_t *s,
                                 uint64_t tensor_id,
                                 const uint8_t *data, size_t data_len,
                                 linoh_tensor_dtype_t dtype,
                                 const uint32_t shape[4],
                                 linoh_tensor_shard_t **shards_out,
                                 size_t *count_out) {
    LINOH_C_GUARD_BEGIN
    if (!s || !shards_out || !count_out) return LINOH_ERR_PARAM;
    if (data_len > 0 && !data) return LINOH_ERR_PARAM;

    std::array<std::uint32_t, 4> cpp_shape = {0, 0, 0, 0};
    if (shape) {
        for (int i = 0; i < 4; ++i) cpp_shape[i] = shape[i];
    }

    auto cpp_dtype = static_cast<multimodal::TensorDType>(dtype);
    auto shards = s->streamer.shard(tensor_id,
                                     std::span<const std::uint8_t>(data, data_len),
                                     cpp_dtype, cpp_shape);

    if (shards.empty()) {
        *shards_out = nullptr;
        *count_out = 0;
        set_error("linoh_tensor_streamer_shard: no shards produced");
        return LINOH_ERR_INTERNAL;
    }

    // 分配 C 数组（calloc 保证零初始化）
    linoh_tensor_shard_t *out = static_cast<linoh_tensor_shard_t*>(
        std::calloc(shards.size(), sizeof(linoh_tensor_shard_t)));
    if (!out) {
        set_error("linoh_tensor_streamer_shard: calloc failed");
        return LINOH_ERR_INTERNAL;
    }

    for (size_t i = 0; i < shards.size(); ++i) {
        auto wire = shards[i].serialize();
        out[i].len = wire.size();
        if (wire.empty()) {
            out[i].data = nullptr;
        } else {
            out[i].data = static_cast<uint8_t*>(std::malloc(wire.size()));
            if (!out[i].data) {
                // 回滚已分配的
                for (size_t j = 0; j < i; ++j) std::free(out[j].data);
                std::free(out);
                set_error("linoh_tensor_streamer_shard: malloc failed");
                return LINOH_ERR_INTERNAL;
            }
            std::memcpy(out[i].data, wire.data(), wire.size());
        }
    }

    *shards_out = out;
    *count_out = shards.size();
    return LINOH_OK;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

void linoh_tensor_shards_free(linoh_tensor_shard_t *shards, size_t count) {
    LINOH_C_GUARD_BEGIN
    if (!shards) return;
    for (size_t i = 0; i < count; ++i) {
        if (shards[i].data) std::free(shards[i].data);
    }
    std::free(shards);
    return;
    LINOH_C_GUARD_END_VOID()
}

linoh_tensor_reassembler_t *linoh_tensor_reassembler_create(void) {
    LINOH_C_GUARD_BEGIN
    return new linoh_tensor_reassembler();
    LINOH_C_GUARD_END(nullptr)
}

void linoh_tensor_reassembler_free(linoh_tensor_reassembler_t *r) {
    LINOH_C_GUARD_BEGIN
    if (!r) return;
    // 先清空 C++ 回调，切断 lambda 对 r 的引用，防止析构链中 UAF
    r->reassembler.on_complete(nullptr);
    r->reassembler.on_merkle_failure(nullptr);
    r->reassembler.on_chunk_verify_failure(nullptr);
    delete r;
    return;
    LINOH_C_GUARD_END_VOID()
}

void linoh_tensor_reassembler_on_complete(linoh_tensor_reassembler_t *r,
                                           linoh_on_tensor_complete_fn cb,
                                           void *user_data) {
    LINOH_C_GUARD_BEGIN
    if (!r) return;
    r->complete_cb = cb;
    r->complete_ud = user_data;
    if (cb) {
        r->reassembler.on_complete([r](std::uint64_t tensor_id,
                                        std::vector<std::uint8_t> data,
                                        multimodal::TensorMeta meta) {
            // malloc 分配（C ABI 兼容），调用方负责 linoh_tensor_data_free
            uint8_t *c_data = nullptr;
            if (!data.empty()) {
                c_data = static_cast<uint8_t*>(std::malloc(data.size()));
                if (c_data) {
                    std::memcpy(c_data, data.data(), data.size());
                }
            }
            r->complete_cb(tensor_id, c_data, data.size(),
                           static_cast<linoh_tensor_dtype_t>(meta.dtype),
                           meta.shape.data(), meta.total_bytes,
                           r->complete_ud);
        });
    } else {
        r->reassembler.on_complete(nullptr);
    }
    return;
    LINOH_C_GUARD_END_VOID()
}

void linoh_tensor_reassembler_on_merkle_failure(linoh_tensor_reassembler_t *r,
                                                  linoh_on_tensor_merkle_failure_fn cb,
                                                  void *user_data) {
    LINOH_C_GUARD_BEGIN
    if (!r) return;
    r->merkle_cb = cb;
    r->merkle_ud = user_data;
    if (cb) {
        r->reassembler.on_merkle_failure([r](std::uint64_t tensor_id,
                                              const std::array<std::uint8_t, 32> &expected,
                                              const std::array<std::uint8_t, 32> &actual) {
            r->merkle_cb(tensor_id, expected.data(), actual.data(), r->merkle_ud);
        });
    } else {
        r->reassembler.on_merkle_failure(nullptr);
    }
    return;
    LINOH_C_GUARD_END_VOID()
}

void linoh_tensor_reassembler_on_chunk_failure(linoh_tensor_reassembler_t *r,
                                                 linoh_on_tensor_chunk_failure_fn cb,
                                                 void *user_data) {
    LINOH_C_GUARD_BEGIN
    if (!r) return;
    r->chunk_cb = cb;
    r->chunk_ud = user_data;
    if (cb) {
        r->reassembler.on_chunk_verify_failure([r](std::uint64_t tensor_id,
                                                     std::uint32_t shard_idx,
                                                     std::size_t chunk_idx,
                                                     const crypto::ChunkHash &expected,
                                                     const crypto::ChunkHash &actual) {
            r->chunk_cb(tensor_id, shard_idx, chunk_idx,
                        expected.data(), actual.data(), r->chunk_ud);
        });
    } else {
        r->reassembler.on_chunk_verify_failure(nullptr);
    }
    return;
    LINOH_C_GUARD_END_VOID()
}

int linoh_tensor_reassembler_on_shard(linoh_tensor_reassembler_t *r,
                                       const uint8_t *data, size_t len) {
    LINOH_C_GUARD_BEGIN
    if (!r || !data || len == 0) return LINOH_ERR_PARAM;

    multimodal::TensorShardMessage msg;
    if (!multimodal::TensorShardMessage::parse(
            std::span<const std::uint8_t>(data, len), msg)) {
        return LINOH_ERR_PARAM;
    }

    return r->reassembler.on_shard(msg) ? 1 : 0;
    LINOH_C_GUARD_END(LINOH_ERR_INTERNAL)
}

float linoh_tensor_reassembler_progress(const linoh_tensor_reassembler_t *r,
                                         uint64_t tensor_id) {
    LINOH_C_GUARD_BEGIN
    if (!r) return 0.0f;
    return r->reassembler.progress(tensor_id);
    LINOH_C_GUARD_END(0.0f)
}

size_t linoh_tensor_reassembler_pending_count(const linoh_tensor_reassembler_t *r) {
    LINOH_C_GUARD_BEGIN
    if (!r) return 0;
    return r->reassembler.pending_count();
    LINOH_C_GUARD_END(0)
}

void linoh_tensor_reassembler_set_auto_cleanup_timeout(linoh_tensor_reassembler_t *r,
                                                         size_t seconds) {
    LINOH_C_GUARD_BEGIN
    if (!r || seconds == 0) return;
    r->reassembler.set_auto_cleanup_timeout(std::chrono::seconds(seconds));
    return;
    LINOH_C_GUARD_END_VOID()
}

size_t linoh_tensor_reassembler_run_auto_cleanup(linoh_tensor_reassembler_t *r) {
    LINOH_C_GUARD_BEGIN
    if (!r) return 0;
    return r->reassembler.run_auto_cleanup();
    LINOH_C_GUARD_END(0)
}

void linoh_tensor_reassembler_set_expected_merkle_root(linoh_tensor_reassembler_t *r,
                                                         uint64_t tensor_id,
                                                         const uint8_t merkle_root[32]) {
    LINOH_C_GUARD_BEGIN
    if (!r || !merkle_root) return;
    std::array<std::uint8_t, 32> root;
    std::memcpy(root.data(), merkle_root, 32);
    r->reassembler.set_expected_merkle_root(tensor_id, root);
    return;
    LINOH_C_GUARD_END_VOID()
}

void linoh_tensor_reassembler_set_verify_merkle(linoh_tensor_reassembler_t *r,
                                                  int enable) {
    LINOH_C_GUARD_BEGIN
    if (!r) return;
    r->reassembler.set_verify_merkle(enable != 0);
    return;
    LINOH_C_GUARD_END_VOID()
}

void linoh_tensor_reassembler_set_verify_chunk_hashes(linoh_tensor_reassembler_t *r,
                                                        int enable) {
    LINOH_C_GUARD_BEGIN
    if (!r) return;
    r->reassembler.set_verify_chunk_hashes(enable != 0);
    return;
    LINOH_C_GUARD_END_VOID()
}

void linoh_tensor_data_free(uint8_t *data) {
    LINOH_C_GUARD_BEGIN
    if (data) std::free(data);
    return;
    LINOH_C_GUARD_END_VOID()
}

}  // extern "C"
