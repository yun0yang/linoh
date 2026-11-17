// ============================================================================
// linoh C-API  —  为非 C++ 语言提供的简化绑定
//
// 此头文件提供以下设施:
//   1. 密钥生成 & 管理 (linoh_key_t)
//   2. 随机数源
//   3. HMAC-SHA256
//   4. AEAD (ChaCha20-Poly1305 风格) seal/open
//   5. 会话票据 (SessionTicket) 导出/导入 (0-RTT)
//
// ABI 稳定性: 结构体大小与字段在同一次构建内保持一致。
// ============================================================================
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- 版本信息 ---------------------------------------------------------------
#define LINOH_VERSION_MAJOR 2
#define LINOH_VERSION_MINOR 0
#define LINOH_VERSION_PATCH 0
const char *linoh_version(void);

// --- 错误码 -----------------------------------------------------------------
typedef enum {
    LINOH_OK            = 0,
    LINOH_ERR_PARAM     = -1,   // 无效参数 (NULL 指针 / 缓冲区过小)
    LINOH_ERR_CRYPTO    = -2,   // 加密/认证失败
    LINOH_ERR_INTERNAL  = -3,   // 内部错误
} linoh_error_t;

// --- 密钥 -------------------------------------------------------------------
enum { LINOH_KEY_SIZE = 32 };

typedef struct {
    uint8_t bytes[LINOH_KEY_SIZE];
} linoh_secret_key_t;

typedef struct {
    uint8_t bytes[LINOH_KEY_SIZE];
} linoh_public_key_t;

typedef linoh_public_key_t linoh_endpoint_id_t;   // EndpointId = PublicKey

// 生成 Ed25519 风格的密钥对 (纯 C++ CSPRNG)
linoh_error_t linoh_generate_keypair(linoh_secret_key_t *sk,
                                     linoh_public_key_t *pk);

// 从 32 字节原始字节构造密钥 (不会额外派生)
linoh_error_t linoh_secret_key_from_bytes(const uint8_t *data,
                                          size_t len,
                                          linoh_secret_key_t *out);

// 从私钥派生公钥 (Ed25519 曲线运算)
// v4.5.0: 应用层无需同时存储 sk+pk，仅存 sk，加载时派生公钥
linoh_error_t linoh_derive_public_key(const linoh_secret_key_t *sk,
                                       linoh_public_key_t *out_pk);

// 从 32 字节原始字节构造公钥
linoh_error_t linoh_public_key_from_bytes(const uint8_t *data,
                                           size_t len,
                                           linoh_public_key_t *out);

// --- 密钥文件持久化 (v4.5.0) ---
// 文件格式 v1 (42 字节):
//   magic(4B "LNOH") + version(1B=0x01) + flags(1B=0x00) + sk(32B) + crc32(4B)
// 旧格式兼容: 64B(sk+pk) / 32B(sk) 自动识别并静默迁移为 v1
// 安全保证: 原子写(.tmp+rename) + 跨平台权限(Linux 0600 / Windows DACL)
enum {
    LINOH_KEY_FILE_MAGIC_1   = 0x484F4E4C,  // "LNOH" 小端 uint32
    LINOH_KEY_FILE_VERSION_1 = 1,
    LINOH_KEY_FILE_V1_SIZE   = 42,          // magic(4)+ver(1)+flags(1)+sk(32)+crc(4)
};

// 持久化私钥到文件 (原子写 + 跨平台权限限制 + CRC32)
linoh_error_t linoh_save_key_file(const char *path,
                                   const linoh_secret_key_t *sk);

// 从文件加载私钥 (自动识别 v1/旧64B/旧32B 格式，旧格式静默迁移)
// CRC32 校验失败返回 LINOH_ERR_CRYPTO
linoh_error_t linoh_load_key_file(const char *path,
                                   linoh_secret_key_t *out_sk);

// 加载或生成: 文件存在→加载；不存在→生成新密钥对并保存
// out_pk 返回派生的公钥
linoh_error_t linoh_load_or_generate_key_file(const char *path,
                                               linoh_secret_key_t *out_sk,
                                               linoh_public_key_t *out_pk);

// 把公钥格式化为短十六进制字符串 (最少 16 字节缓冲区)
// 返回写入的字节数 (不含 NUL)，失败返回 0
size_t linoh_public_key_fmt_short(const linoh_public_key_t *pk,
                                  char *buf, size_t buf_size);

// --- 随机数 -----------------------------------------------------------------
// 用系统 CSPRNG 填充缓冲区 (Windows: BCryptGenRandom, Linux: /dev/urandom)
linoh_error_t linoh_random_bytes(uint8_t *out, size_t len);

// --- HMAC-SHA256 ------------------------------------------------------------
enum { LINOH_HMAC_SHA256_SIZE = 32 };

typedef struct { uint8_t bytes[32]; } linoh_hmac_t;

// 计算 HMAC-SHA256(key, msg)
linoh_error_t linoh_hmac_sha256(const uint8_t *key, size_t key_len,
                                const uint8_t *msg, size_t msg_len,
                                linoh_hmac_t *out);

// --- AEAD (ChaCha20-Poly1305, RFC 8439) -------------------------------------
enum {
    LINOH_AEAD_KEY_SIZE   = 32,
    LINOH_AEAD_NONCE_SIZE = 12,
    LINOH_AEAD_TAG_SIZE   = 16,
};

typedef struct { uint8_t bytes[LINOH_AEAD_KEY_SIZE]; } linoh_aead_key_t;

// 加密: out = ciphertext || tag
// out_len 必须 >= plaintext_len + LINOH_AEAD_TAG_SIZE
// 返回实际写入的字节数 (plaintext_len + tag)，失败返回 0
size_t linoh_aead_seal(const linoh_aead_key_t *key,
                       const uint8_t nonce[LINOH_AEAD_NONCE_SIZE],
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *plaintext, size_t plaintext_len,
                       uint8_t *out, size_t out_size);

// 解密: cipher_with_tag = ciphertext || tag
// 返回实际写入的明文字节数，认证失败返回 0
size_t linoh_aead_open(const linoh_aead_key_t *key,
                       const uint8_t nonce[LINOH_AEAD_NONCE_SIZE],
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *cipher_with_tag, size_t ct_len,
                       uint8_t *out, size_t out_size);

// --- 会话票据 (0-RTT Session Ticket) ----------------------------------------
//
// 会话票据 = 对方 EndpointId (32B) + master_secret (32B) + max_early_data (4B)
// 导出/导入时使用序列化格式 (大端): [peer_id(32)][master_secret(32)][max_early_data(4)]
enum {
    LINOH_TICKET_PEER_ID_OFFSET    = 0,
    LINOH_TICKET_MASTER_SECRET_OFFSET = 32,
    LINOH_TICKET_MAX_EARLY_OFFSET  = 64,
    LINOH_TICKET_SIZE              = 68,
};

typedef struct {
    linoh_endpoint_id_t peer_id;
    uint8_t             master_secret[LINOH_KEY_SIZE];
    uint32_t            max_early_data_bytes;
} linoh_session_ticket_t;

// 把会话票据序列化为二进制 (LINOH_TICKET_SIZE 字节)
void linoh_ticket_to_bytes(const linoh_session_ticket_t *ticket,
                           uint8_t out[LINOH_TICKET_SIZE]);

// 从二进制解析会话票据
void linoh_ticket_from_bytes(const uint8_t data[LINOH_TICKET_SIZE],
                             linoh_session_ticket_t *out);

// 从 master_secret 派生 0-RTT AEAD 密钥
// zero_rtt_key = HMAC-SHA256(master_secret, "zero-rtt")
linoh_error_t linoh_derive_zero_rtt(const uint8_t master_secret[LINOH_KEY_SIZE],
                                    linoh_aead_key_t *out);

// ============================================================================
// v1.0 C-API  —  opaque-handle 风格的连接 / Endpoint / Stream 接口
//
// 对象生命周期通过 opaque 句柄管理，错误通过返回值传递。
// 所有回调函数由调用者提供，linoh 在内部线程或调用线程中触发。
// ============================================================================

// --- 不透明句柄 --------------------------------------------------------
typedef struct linoh_endpoint   linoh_endpoint_t;   // Endpoint: 监听 & 发起连接的根对象
typedef struct linoh_connection linoh_connection_t; // Connection: 一个 QUIC 连接
typedef struct linoh_stream    linoh_stream_t;     // Stream: 连接内的双向字节流

// --- 连接状态 ----------------------------------------------------------
typedef enum {
    LINOH_CONN_INITIAL     = 0,
    LINOH_CONN_HANDSHAKE  = 1,
    LINOH_CONN_ESTABLISHED= 2,
    LINOH_CONN_CLOSING    = 3,
    LINOH_CONN_DRAINING   = 4,
    LINOH_CONN_CLOSED     = 5,
} linoh_conn_state_t;

// --- 传输地址 ----------------------------------------------------------
typedef struct {
    char   host[64];   // IPv4/IPv6 地址字符串，NUL 结尾
    uint16_t port;     // 网络字节序 (big-endian)
} linoh_addr_t;

// --- Endpoint 配置 ---------------------------------------------------
typedef struct {
    linoh_secret_key_t  secret_key;    // 本节点 Ed25519 私钥 (32 字节)
    const char         *alpn;         // 应用层协议标识，如 "echo/1" (非空字符串)
    uint16_t            udp_port;     // 本地 UDP 监听端口，0 表示随机分配
    void               *user_data;    // 传递给所有回调的上下文指针
    // K-LINOH-PERF-001: 本端期望 MTU，用于 MTU 协商。
    //   1280（默认）= QUIC 最小保证，跨网安全
    //   1500 = 标准以太网 MTU
    //   9000 = jumbo frame（仅内网/局域网，需网卡 + 交换机支持）
    //   握手后与对端取 min，最终 MTU = max(1280, min(local, remote))
    uint16_t            local_preferred_mtu;  // 0 表示用默认值 1280

    // 【硬件规定】linoh 原生 relay 配置 — NAT 穿透/跨网段通信使用 linoh relay server
    // 配置后 endpoint 将通过 relay server 中转数据，不使用任何外部隧道
    // relay_urls: relay server URL 列表，如 "ws://203.0.113.10:9002"
    //   - 协议: ws:// (明文) 或 wss:// (TLS)
    //   - 首个可连接的 relay server 会被使用
    const char *const *relay_urls;
    uint32_t           relay_url_count;
    // relay_peer_id_hex: 目标节点的 EndpointId（64 字符 hex 字符串，即 Ed25519 公钥）
    //   - 通过 relay 转发数据时的目标地址
    //   - 为 NULL 时 relay 仅用于入站中转，不主动 send_via
    const char         *relay_peer_id_hex;

    // 【多模态隧道】path_strategy_name: 路径选择策略名称（v4.8.0 新增）
    //   - "prefer-direct": P2P 直连优先，relay 兜底（推荐，默认值）
    //   - "prefer-relay" : 始终走 Relay（适合 hard NAT）
    //   - "rtt"          : 按 RTT 选路（v4.6.x 行为）
    //   - "bandwidth-tier": 按带宽 tier 三键排序（适合 hidden_state 大 tensor）
    //   - "pp-first"     : PP 链首节点策略（优先低延迟）
    //   - "pp-last"      : PP 链末节点策略（优先高带宽）
    //   - 为 NULL 时默认 "prefer-direct"（与 relay_urls 配合实现多模态隧道）
    //   - 启用后 PathMigrationManager 按策略选路，relay_urls 作为 fallback 路径
    const char         *path_strategy_name;

    // K-LINOH-READBLK-001 (v5.3.1): 连接活性巡检配置。
    //   idle_timeout_ms:       无任何包交互后判定连接死亡的毫秒数。
    //                          超时后连接转 CLOSED、所属流标记 dead（read 可感知）。
    //   keepalive_interval_ms: 保活 PING 间隔毫秒数。UDP 上对端被 kill 无 FIN 可收，
    //                          保活让"对端死"可被感知并刷新本端活性。
    //   取值语义：0 = 用默认值（idle 30000 / keepalive 10000）——零初始化 struct 的
    //   旧调用方无需改代码即获得修复；UINT32_MAX = 显式关闭对应机制（恢复 v5.3.0
    //   行为，灰度开关）；其它值 = 自定义毫秒数。
    uint32_t            idle_timeout_ms;
    uint32_t            keepalive_interval_ms;

    // v5.5 F6.2: ACK 空窗路径切换阈值毫秒（0 = 关闭，默认）。
    // 持续发送但连续该时长未收到任何 ACK → 判定主路径劣化，翻转发送目标
    // （direct↔relay）。不依赖 ICMP（Windows 节流），双平台一致；
    // 建议值 ≥ 4×RTT。对端死亡检出后此通道与巡检/read_ex 语义正交。
    uint32_t            path_ack_timeout_ms;
} linoh_endpoint_config_t;

// --- Endpoint 回调 ----------------------------------------------------
typedef void (*linoh_on_connection_fn)(
    linoh_connection_t *conn, void *user_data);
typedef void (*linoh_on_stream_fn)(
    linoh_stream_t *stream, void *user_data);
typedef void (*linoh_on_conn_state_fn)(
    linoh_connection_t *conn, linoh_conn_state_t state, void *user_data);
typedef void (*linoh_on_close_fn)(
    linoh_connection_t *conn, void *user_data);

// ============================================================================
// Endpoint API
// ============================================================================

// 创建 Endpoint (UDP 监听器 + 连接发起器)
// - 成功返回非空句柄；失败返回 NULL
// - 内部分配内存，调用 linoh_endpoint_free() 释放
linoh_endpoint_t *linoh_endpoint_create(const linoh_endpoint_config_t *config);

// 释放 Endpoint 句柄，关闭所有底层连接
void linoh_endpoint_free(linoh_endpoint_t *ep);

// [FIX 2026-08-13] 查询 relay 连接是否活跃
// 返回值：true=relay 活跃，false=relay 已断开（需重建 endpoint）
bool linoh_endpoint_is_relay_active(const linoh_endpoint_t *ep);

// [FIX 2026-08-14] 重置 stream 的 send_offset 为 0
// 用于 PP 推理场景：master 在同一个 stream 上发送多条独立消息（ASSIGN/FORWARD/RESULT），
// 每条消息应从 offset=0 开始，对端通过隐式重置正确接收。
// 调用时机：每次 linoh_stream_write 前调用此函数。
void linoh_stream_reset_send_offset(linoh_stream_t *s);

// [FIX 2026-08-14] 重置 stream 的接收侧状态（recv_ buffer + OOS buffers + recv_offset_）
// 用于 PP 推理场景：win-worker 在 read_exact 前调用，清空上一条消息的残留数据
// 和 OOS 缓冲区（可能包含心跳包导致的 PN 不连续条目），确保新消息从干净状态开始。
// 线程安全：内部获取 stream_mu_ 锁，与 handle_1rtt_packet 互斥。
void linoh_stream_reset_recv(linoh_stream_t *s);

// [FIX 2026-08-14] 抑制/恢复 implicit reset：win-worker 读取 binary 帧期间调用 suppress=true，
// 防止 HEARTBEAT_ACK retransmission 触发 implicit reset 破坏 binary 数据。读取完成后调用 suppress=false。
void linoh_stream_suppress_reset(linoh_stream_t *s, int suppress);

// 获取本节点 EndpointId (公钥)
const linoh_endpoint_id_t *linoh_endpoint_id(const linoh_endpoint_t *ep);

// 获取本地 UDP 端口 (主机字节序)
uint16_t linoh_endpoint_udp_port(const linoh_endpoint_t *ep);

// 注册连接到达回调 (非阻塞轮询时会被内部 accept 循环触发)
// 回调在 Endpoint 线程中被调用
void linoh_endpoint_on_connection(linoh_endpoint_t *ep,
                                  linoh_on_connection_fn cb);

// 注册流数据到达回调
// 每次收到 STREAM 帧时触发，回调中可调用 linoh_stream_read()
void linoh_endpoint_on_stream(linoh_endpoint_t *ep,
                              linoh_on_stream_fn cb);

// 注册连接状态变化回调
void linoh_endpoint_on_conn_state(linoh_endpoint_t *ep,
                                  linoh_on_conn_state_fn cb);

// 注册连接关闭回调
void linoh_endpoint_on_close(linoh_endpoint_t *ep,
                             linoh_on_close_fn cb);

// 设置/更新 endpoint 的 user_data 指针（覆盖 config.user_data）
// 用于回调桥接场景：create 后才能确定的上下文可通过此 API 注入。
// 典型用途：JNI 桥接层在 endpoint_create 后才能确定 handle 指针，
// 通过此 API 把 handle 指针注入，回调触发时通过 user_data 反查上下文。
// 线程安全：内部 atomic store，可在任意线程调用，与回调线程的读取无锁同步。
void linoh_endpoint_set_user_data(linoh_endpoint_t *ep, void *user_data);

// 轮询一次: 处理内部 UDP 接收、accept、回调触发
// 返回值: 0 = 无事发生, 正数 = 触发的事件数
// 推荐在游戏循环 / select() / poll() 中每帧调用
int linoh_endpoint_poll(linoh_endpoint_t *ep);

// 接受一个已到达的入站连接 (返回 NULL 表示队列为空)
// 返回的 connection 生命周期归调用者
linoh_connection_t *linoh_endpoint_accept(linoh_endpoint_t *ep);

// 主动连接到远程端点 (客户端使用)
// host: IP 地址 (如 "127.0.0.1")
// port: 端口号
// 返回: 新连接句柄, NULL = 失败
linoh_connection_t *linoh_endpoint_connect(linoh_endpoint_t *ep,
                                            const char *host, uint16_t port);

// ============================================================================
// P5-A-1: 多模态双连接 API
// ============================================================================
//
// 多模态连接对 = 控制连接 (ctrl/1) + 数据连接 (pp-*/1)
// 控制连接承载 RPC/心跳/状态上报；数据连接承载推理数据
// 两连接独立 stream 池，互不阻塞
//
// 数据通道类型（linoh_multimodal_channel_t）:
//   0 = CONTROL       (内部使用，不应由用户直接指定)
//   1 = LLM_HIDDEN    (LLM hidden_state，小包低延迟)
//   2 = IMG_FEATURE   (图片模型特征图，大包突发)
//   3 = VIDEO_FEATURE (视频模型特征，持续大流量)
//   4 = AUDIO_FEATURE (音频特征)
//   5 = FUSION        (多模态融合层)

typedef uint8_t linoh_multimodal_channel_t;
enum {
    LINOH_CHANNEL_CONTROL       = 0,
    LINOH_CHANNEL_LLM_HIDDEN    = 1,
    LINOH_CHANNEL_IMG_FEATURE   = 2,
    LINOH_CHANNEL_VIDEO_FEATURE = 3,
    LINOH_CHANNEL_AUDIO_FEATURE = 4,
    LINOH_CHANNEL_FUSION        = 5,
    // v1.6.0.1 (P0): EP（Expert Parallelism）通道，与 C++ ChannelType 严格对齐
    LINOH_CHANNEL_EP_DISPATCH   = 6,  // EP token 分发（master → worker）
    LINOH_CHANNEL_EP_COMBINE    = 7,  // EP 结果聚合（worker → master）
    LINOH_CHANNEL_EP_SYNC       = 8,  // EP 跨节点同步原语（barrier/signal/all-reduce）
};

// 多模态连接对句柄（包含 ctrl + data 两个连接）
typedef struct linoh_multimodal_conn linoh_multimodal_conn_t;

// 建立多模态连接对（异步，阻塞等待完成）
// host: 对端 IP 地址
// port: 对端端口
// data_channel: 数据通道类型（不应为 0/CONTROL）
// 返回: 连接对句柄, NULL = 失败
//
// 注意: 此函数会阻塞直到两个连接都建立完成或失败。
//       失败时会自动清理已建立的连接。
linoh_multimodal_conn_t *linoh_endpoint_connect_multimodal(
    linoh_endpoint_t *ep,
    const char *host, uint16_t port,
    linoh_multimodal_channel_t data_channel);

// 获取多模态连接对中的控制连接（ALPN=ctrl/1）
// 返回 NULL 表示无效句柄。返回的 connection 句柄生命周期与 conn_pair 绑定。
linoh_connection_t *linoh_multimodal_ctrl_conn(linoh_multimodal_conn_t *conn_pair);

// 获取多模态连接对中的数据连接（ALPN=pp-*/1）
// 返回 NULL 表示无效句柄。返回的 connection 句柄生命周期与 conn_pair 绑定。
linoh_connection_t *linoh_multimodal_data_conn(linoh_multimodal_conn_t *conn_pair);

// 获取数据通道类型
linoh_multimodal_channel_t linoh_multimodal_data_channel(
    const linoh_multimodal_conn_t *conn_pair);

// 释放多模态连接对（会关闭 ctrl + data 两个连接）
void linoh_multimodal_conn_free(linoh_multimodal_conn_t *conn_pair);

// 获取通道类型对应的 ALPN 字符串（用于调试）
// 返回静态字符串，不需要释放
const char *linoh_channel_alpn(linoh_multimodal_channel_t channel);

// ============================================================================
// Connection API
// ============================================================================

// 释放连接句柄 (会发送 CONNECTION_CLOSE)
void linoh_connection_free(linoh_connection_t *conn);

// 获取连接当前状态
linoh_conn_state_t linoh_connection_state(const linoh_connection_t *conn);

// 获取对端 EndpointId
const linoh_endpoint_id_t *linoh_connection_peer_id(const linoh_connection_t *conn);

// v5.1.0: 对端身份是否已通过 PSK_IDENTITY 帧验签认证。
// PSK 模式下 peer_id 仅在返回非 0 时可信（K-LINOH-PEERMISMATCH 根治出口）；
// 返回 0 = 对端为旧版本未发送身份帧（降级兼容），peer_id 保持旧行为不可信。
int linoh_connection_peer_authenticated(const linoh_connection_t *conn);

// 获取连接 ALPN 协议标识
const char *linoh_connection_alpn(const linoh_connection_t *conn);

/**
 * @brief v1.5 P1-1: 用指定 ALPN 字符串建立客户端连接（不动 ep->alpn）
 *
 * 背景：cluster win-worker 部署时 linoh_endpoint_t 通常配置默认 ALPN（如 "echo/1"），
 * 但多模态推理时每个数据连接需要独立 ALPN（pp-hidden/1、pp-img/1 等）。
 * 旧实现 linoh_endpoint_connect_multimodal 用 swap ep->alpn 模式，副作用大且非线程安全。
 *
 * 新实现：本函数接受独立 alpn 参数，在 cfg.alpn 中设置，ep->alpn 不动。
 * 若 alpn 为 NULL 或空字符串，则回退到使用 ep->alpn（保持向后兼容）。
 *
 * @param ep     linoh_endpoint_t 指针
 * @param host   服务器主机名或 IP（IPv4 点分十进制）
 * @param port   服务器 UDP 端口
 * @param alpn   ALPN 字符串（可空）；非空时作为本次连接的 ALPN
 * @return 新建连接句柄，失败返回 NULL
 */
linoh_connection_t *linoh_endpoint_connect_with_alpn(linoh_endpoint_t *ep,
                                                      const char *host,
                                                      uint16_t port,
                                                      const char *alpn);

// v1.5 P1-2: 引用计数管理（避免 self_ref 引用计数问题）
// retain 增引用计数（必须与 release 成对调用）
// release 减引用计数，归零时不立即释放（仍由 ep->conns map 持有）
void linoh_connection_retain(linoh_connection_t *conn);
void linoh_connection_release(linoh_connection_t *conn);

// 获取当前引用计数（用于测试与诊断）
int linoh_connection_refcount(const linoh_connection_t *conn);

// 获取连接统计信息
void linoh_connection_stats(const linoh_connection_t *conn,
                           uint64_t *packets_sent,
                           uint64_t *packets_received,
                           uint64_t *bytes_sent,
                           uint64_t *bytes_received);

/// O3: 连接统计 v2（补充丢失/重传计数，供 FEC 自适应控制器喂数）
// @param conn              连接句柄
// @param out_lost_packets  可空；累计丢包数（ConnectionStats.lost_packets）
// @param out_retransmitted 可空；累计重传包数
// @return 0=成功，<0=错误码
linoh_error_t linoh_connection_stats_v2(const linoh_connection_t *conn,
                                         uint64_t *out_lost_packets,
                                         uint64_t *out_retransmitted);

/// O1.2: 设置/查询对端压缩能力掩码（kCap* 组合；驱动自动压缩降级矩阵）
// 说明：库内收到 CapabilitiesAck 响应时会自动缓存；此函数供调用方在
// 自有协商完成后显式覆盖（例如调用方 probe future 解析后写回）。
// @param mask 能力位掩码（0=未探测，自动压缩将不启用）
// @return 0=成功，<0=错误码
linoh_error_t linoh_connection_set_peer_capabilities(linoh_connection_t *conn,
                                                      uint32_t mask);

/// O1.2: 查询对端能力掩码
linoh_error_t linoh_connection_get_peer_capabilities(const void *conn,
                                                      uint32_t *out_mask);

// 关闭连接 (error_code=0 表示正常关闭)
// reason 为可读文本，长度 0 表示无原因字符串
void linoh_connection_close(linoh_connection_t *conn,
                           uint16_t error_code,
                           const char *reason);

// P4-A-3: 立即关闭连接（跳过 draining period）
//
// 与 linoh_connection_close 不同，本函数跳过 Closing 中间状态直接进入 Closed，
// 适用于应用主动退出场景。代价：对端可能要靠心跳超时才发现本端退出。
void linoh_connection_close_immediate(linoh_connection_t *conn,
                                       uint16_t error_code,
                                       const char *reason);

// ============================================================================
// Stream API
// ============================================================================

// 获取 Stream 所属的 Connection (调用者不负责释放)
const linoh_connection_t *linoh_stream_connection(const linoh_stream_t *stream);

// 获取 Stream ID (QUIC stream 编号)
uint64_t linoh_stream_id(const linoh_stream_t *stream);

// 检查 Stream 是否有可读数据
// 返回非零表示有数据可读
int linoh_stream_has_readable(const linoh_stream_t *stream);

// 读取 Stream 中的数据 (阻塞直到有数据或 FIN)
// - buf: 输出缓冲区
// - buf_size: 缓冲区大小 (必须 > 0)
// - 返回实际读取的字节数，0 表示对端已关闭 (FIN)
// [K-LINOH-READBLK-001 注意] 本函数实为**非阻塞**：无数据立即返回 0，
// 且 0 无法区分"暂无数据"与"连接已死"。长连接业务请改用
// linoh_stream_read_ex()（带超时 + 显式四态返回）。
size_t linoh_stream_read(linoh_stream_t *stream,
                         uint8_t *buf, size_t buf_size);

// K-LINOH-READBLK-001 (v5.3.1): 带超时与显式状态的流读取。
// - timeout_ms: 最长等待毫秒数（0 = 不等待，等同状态增强版的 read）
// - st: 出参状态（可为 NULL）；返回值为读到的字节数
//   LINOH_READ_OK        读到 n>0 字节
//   LINOH_READ_EMPTY     超时仍无数据（连接仍活，可继续调用）
//   LINOH_READ_FIN       对端 graceful 关闭（FIN）且无残留数据
//   LINOH_READ_CONN_DEAD 连接已死（idle 超时/本端关闭）→ 业务应重连
//   LINOH_READ_INVALID   参数非法或流句柄失效
// 唤醒源：数据到达 / 连接关闭 / 巡检 tick（≤500ms 粒度）/ 超时。
typedef enum {
    LINOH_READ_OK        = 0,
    LINOH_READ_EMPTY     = 1,
    LINOH_READ_FIN       = 2,
    LINOH_READ_CONN_DEAD = 3,
    LINOH_READ_INVALID   = 4,
} linoh_read_status_t;

size_t linoh_stream_read_ex(linoh_stream_t *stream, uint8_t *buf, size_t buf_size,
                            uint32_t timeout_ms, linoh_read_status_t *st);

// K-LINOH-READBLK-001 (v5.3.1): 流所属连接是否已死（idle 超时/关闭）。
// 返回 1=已死（应重连），0=存活。缓冲区中未读数据仍可正常读取。
int linoh_stream_is_dead(const linoh_stream_t *stream);

// ---- v5.4 F7（借鉴 ScaleFabric 可观测方法论）：指标导出 --------------------
// 消息尺寸直方图 8 桶上界（字节）：64/256/1K/4K/16K/64K/256K/∞
#define LINOH_MSG_BUCKETS 8

// 单连接统计快照（尽力而为：包处理线程并发写，读侧值拷贝，非严格一致）
typedef struct {
    // 基础传输
    uint64_t packets_sent, packets_received;
    uint64_t bytes_sent, bytes_received;
    uint64_t lost_packets, retransmitted_packets;
    double   rtt_ema_ms, rttvar_ms, rto_ms;
    uint64_t bandwidth_bps, pacing_rate_bps;
    uint32_t cwnd_bytes;
    // 消息级画像：sent 按应用 write() 的消息尺寸计；
    // received 按应用 read() 的消费块尺寸计（流式读取无消息边界，大消息分多次进小桶）
    uint64_t msgs_sent, msgs_received;
    uint64_t msg_size_sent_buckets[LINOH_MSG_BUCKETS];
    uint64_t msg_size_recv_buckets[LINOH_MSG_BUCKETS];
    // 路径占比（direct UDP vs relay 代理）
    uint64_t pkts_via_direct, pkts_via_relay;
    // 活性与状态
    int      conn_state;            // linoh_conn_state_t
    uint32_t streams_open;          // 打开的流数
    uint32_t idle_timeout_ms;       // 活性配置（0=关闭）
    uint32_t keepalive_ms;          // 保活配置（0=关闭）
    double   last_activity_age_ms;  // 距最近收包毫秒数
    // v5.4 F6: 路径热切换
    uint64_t path_switch_count;     // 累计切换次数（连续发送失败达阈值触发）
    int      active_path;           // 当前发送路径：-1=跟随 endpoint 全局 / 0=direct / 1=relay
} linoh_connection_stats_t;

// endpoint 汇总统计（遍历当前连接聚合；无连接返回 0）
typedef struct {
    uint32_t conns_total;            // endpoint 当前持有连接数
    uint32_t conns_established;      // 其中 ESTABLISHED 状态数
    uint64_t packets_sent, packets_received;
    uint64_t bytes_sent, bytes_received;
    uint64_t lost_packets, retransmitted_packets;
    double   rtt_ema_ms_max;         // 最差 RTT（跨连接最大值）
    uint64_t msgs_sent, msgs_received;
    uint64_t msg_size_sent_buckets[LINOH_MSG_BUCKETS];
    uint64_t msg_size_recv_buckets[LINOH_MSG_BUCKETS];
    uint64_t pkts_via_direct, pkts_via_relay;
} linoh_endpoint_stats_t;

// 导出单连接统计。成功返回 1；参数无效返回 0。
int linoh_connection_get_stats(const linoh_connection_t *conn,
                               linoh_connection_stats_t *out);

// 导出 endpoint 汇总统计。成功返回 1；参数无效返回 0。
int linoh_endpoint_get_stats(linoh_endpoint_t *ep,
                             linoh_endpoint_stats_t *out);

// 向 Stream 写入数据
// - 返回写入的字节数 (可能小于 data_len 如果流缓冲区满)
// - 调用 linoh_connection_flush() 实际发送
// v5.4 F4：linoh_stream_write_ex 带阻塞语义——流控窗口不足时发送
// STREAM_DATA_BLOCKED 声明需求（对端 v5.4+ 保障窗口并回 MAX_STREAM_DATA），
// 等待窗口增长直至超时；返回实际写入字节数（0=超时未写任何字节）。
size_t linoh_stream_write_ex(linoh_stream_t *stream, const uint8_t *data,
                             size_t data_len, uint32_t timeout_ms);

// v5.4 F4（借鉴 ScaleFabric credit 预约式无损流控）：预留流信用窗口。
// 声明"本流预计再发 reserve_bytes"（STREAM_DATA_BLOCKED 携带期望 offset），
// 对端 v5.4+ 收到即保障窗口至少到该 offset 并立即回 MAX_STREAM_DATA。
// 阻塞等待窗口生效，返回生效后可写容量（0=超时/对端不支持）。
uint64_t linoh_stream_request_reserve(linoh_stream_t *stream,
                                      uint64_t reserve_bytes, uint32_t timeout_ms);

// ---- v5.4 F3'（借鉴 ScaleFabric 算-传紧耦合）：异步发送 --------------------
// 异步 flush：write 后调用即返回（数据由 linoh 内部线程分批 flush 发出），
// 调用线程（推理计算线程）零阻塞——传输与计算重叠的基础原语。
// 返回 0=提交成功；-1=参数无效或线程启动失败。
// 内部：10ms 节拍循环 flush 直至排空（has_pending_data 清除即静默）；
// 连接关闭/endpoint 释放时自动停止。与显式 linoh_connection_flush 可混用。
int linoh_connection_flush_async(linoh_connection_t *conn);
size_t linoh_stream_write(linoh_stream_t *stream,
                          const uint8_t *data, size_t data_len);

// 通知对端本端已完成写入 (发送 STREAM with FIN)
// 调用后不能再写数据
void linoh_stream_finish(linoh_stream_t *stream);

// 检查 Stream 是否已半关闭 (本端写 FIN 已发)
int linoh_stream_is_finished(const linoh_stream_t *stream);

// 检查 Stream 是否已完全关闭 (读写均结束)
int linoh_stream_is_closed(const linoh_stream_t *stream);

// 释放 Stream 句柄
// 必须释放通过 linoh_endpoint_on_stream 回调或 linoh_connection_open_stream 获得的句柄
// 释放后不能继续使用该句柄
void linoh_stream_free(linoh_stream_t *stream);

// ============================================================================
// 连接操作 (在 Connection 级别，不通过 Stream)
// ============================================================================

// 打开一条新的双向 Stream 并返回其句柄
// 调用者负责管理 Stream 生命周期 (在连接关闭前有效)
linoh_stream_t *linoh_connection_open_stream(linoh_connection_t *conn);

// 尝试接收一条已就绪的入站 Stream (返回 NULL 表示队列为空)
linoh_stream_t *linoh_connection_accept_stream(linoh_connection_t *conn);

// ============================================================================
// v3.2.0 Direct Return Path — 末节点直连回传 MASTER 的 C-API
//
// 场景：PP 链末节点推理完成后，绕过逐跳反向中继，直接通过 pp-llm/1 ALPN
//       连接到 MASTER 并通过独立 STREAM 回传 ResultPP[DirectReturn]。
//
// 复用策略：同一 (master_host, master_port) 的连接在 endpoint 内部池中复用，
//           多次推理复用同一条 pp-llm/1 连接，减少 dial/握手开销。
//           空闲连接由 linoh_endpoint_free 统一释放。
//
// stream_token 生成规则（与 C++ DirectReturnManager 一致）：
//           fnv1a_64(req_id(8B,LE) || timestamp_ms(8B,LE)) 取低 32 位
//           调用方按此规则生成后传入；MASTER 端用同一规则路由。
//
// payload 格式：[stream_token(4B,LE)][result_payload]
//           封装为 ApplicationMessage(ResultPP, flags=DirectReturn|EndOfStream?)
// ============================================================================

// 打开到 MASTER 的直连 return STREAM（末节点端）
//
// \param ep            linoh_endpoint_t 句柄
// \param master_host   MASTER 的 IP 地址（如 "203.0.113.10"），调用方动态获取
// \param master_port   MASTER 的 UDP 端口（pp-llm/1 ALPN）
// \param stream_token  MASTER 预分配的 return stream 标识（写入 payload 头部供 MASTER 路由）
// \return linoh_stream_t* 句柄，失败返回 NULL（连接失败/握手失败）
//
// \note 内部按 (master_host, master_port) 复用 pp-llm/1 连接
// \note 返回的 stream 通过 linoh_close_return_stream 关闭（不释放底层连接）
linoh_stream_t *linoh_open_return_stream(linoh_endpoint_t *ep,
                                          const char *master_host,
                                          uint16_t master_port,
                                          uint32_t stream_token);

// 通过 return stream 发送 ResultPP[DirectReturn]
//
// \param ep             linoh_endpoint_t 句柄
// \param stream         linoh_open_return_stream 返回的 stream
// \param stream_token   MASTER 预分配的标识（写入 payload 头部）
// \param result_payload 推理结果字节流
// \param result_len     结果字节长度
// \param combined       1=末节点最终结果（附加 EndOfStream flag），0=中间结果
// \return 0=成功，<0=失败（stream 无效/写入失败）
int linoh_send_result_direct(linoh_endpoint_t *ep,
                              linoh_stream_t *stream,
                              uint32_t stream_token,
                              const uint8_t *result_payload,
                              size_t result_len,
                              int combined);

// P3-1: 通过 return stream 发送分片大 ResultPP[DirectReturn|ResultShard]
//
// 将大 result_payload 按 shard_size 切分为多个独立 ApplicationMessage 发送，
// 每个 shard payload = [stream_token(4B,LE)][shard_idx(2B,LE)][total_shards(2B,LE)][chunk]
// MASTER 端按 stream_token 累积重组，total_shards 到齐后唤醒 await。
//
// \param ep             linoh_endpoint_t 句柄
// \param stream         linoh_open_return_stream 返回的 stream
// \param stream_token   MASTER 预分配的标识
// \param result_payload 大结果字节流
// \param result_len     结果字节长度
// \param combined       1=末节点最终结果
// \param shard_size     每 shard 最大 payload 字节（建议 1024，0=默认 1024）
// \return 0=成功，<0=失败
int linoh_send_result_direct_sharded(linoh_endpoint_t *ep,
                                      linoh_stream_t *stream,
                                      uint32_t stream_token,
                                      const uint8_t *result_payload,
                                      size_t result_len,
                                      int combined,
                                      size_t shard_size);

// 关闭 return stream（仅释放 stream 句柄，底层连接留池中复用）
//
// \param ep     linoh_endpoint_t 句柄
// \param stream linoh_open_return_stream 返回的 stream
void linoh_close_return_stream(linoh_endpoint_t *ep, linoh_stream_t *stream);

// 手动清理 return stream 池中已失效/关闭的连接（可选，linoh_endpoint_free 会统一清理）
// 返回清理的连接数
int linoh_return_stream_pool_cleanup(linoh_endpoint_t *ep);

// 立即刷新发送缓冲区: 构建 1-RTT 包并通过 raw socket 发送
// 成功返回发送字节数，0 表示没有待发送数据或连接未建立
size_t linoh_connection_flush(linoh_connection_t *conn);

// 循环刷新发送缓冲区直到清空: 连续构建 1-RTT 包并发送，包间无 sleep
// 用于大数据块（如 PP hidden_state）一次性发完，避免逐包 flush + sleep 的乒乓延迟
// - max_packets: 安全上限（防死循环），建议 512（512 * ~1.2KB ≈ 600KB）；传 0 用默认值
// - 返回总发送字节数，0 表示没有待发送数据或连接未建立
size_t linoh_connection_flush_all(linoh_connection_t *conn, size_t max_packets);

// 向原始 socket 提交一个收到的 UDP 包 (供外部 Winsock/posix socket 注入)
// 返回 0 表示成功处理，负数表示错误
int linoh_connection_submit_packet(linoh_connection_t *conn,
                                  const uint8_t *pkt, size_t pkt_len);

// ============================================================================
// 辅助: 错误消息 -----------------------------------------------------------
// 返回上一次错误的描述字符串 (thread-local buffer, thread-safe)
const char *linoh_error_str(void);

// ============================================================================
// v1.5.0.2.3: 运行时日志级别切换 + Stream FIN 检测（cluster 兼容性恢复）
// ============================================================================

// 动态设置全局日志级别
// level: 0=Trace, 1=Debug, 2=Info(默认), 3=Warn, 4=Error
// 线程安全：atomic store；调用方可在任意线程切换
void linoh_set_log_level(int level);

// 查询对端是否已发送 FIN（区别于本端 finish_send）
// 返回 1 = 对端已发送 FIN（不会再有数据），0 = 未收到 FIN
// 用于 PP 推理收尾判断：避免 stream_read()==0 时永久循环等待
int linoh_stream_fin_received(const linoh_stream_t *s);

// ============================================================================
// v1.5.0.3: F3 OOS 主动通知 API（视频模型组要求，LINOH_V15027 根因修复路径）
// ============================================================================
//
// 背景：OOS buffer（乱序接收缓冲）持续累积时，应用层无法感知协议层是否仍在
//   等待 retx 填补 gap。F3 API 让应用层主动查询 OOS 状态或注册阈值回调。
//
// 典型用法：
//   1) 主动查询（_read_exact v3 设计）：
//        size_t oos_sz;
//        linoh_stream_oos_size(stream, &oos_sz);
//        if (oos_sz > 0) {
//            uint64_t off; size_t gap;
//            linoh_stream_oos_first_gap(stream, &off, &gap);
//            // off 是首个 OOS gap 起点（= recv_offset_），gap 是该 entry 长度
//        }
//   2) 阈值回调（高实时性场景）：
//        linoh_stream_set_oos_callback(stream, my_cb, user_data, 4096);
//        // 当 OOS 累积 ≥ 4096 字节时，回调被同步触发
//
// 线程安全：所有 API 内部已加 stream_mu_ 锁，可与 stream_read 并发调用。

// 查询 Stream 当前 OOS buffer 字节总数
// 返回 0 表示无乱序数据；非 0 表示等待 gap 填补的字节数
size_t linoh_stream_oos_size(const linoh_stream_t *s);

// 查询 Stream 第一个 OOS gap（OOS buffer 中 offset 最小 entry）
// - out_offset: 第一个 entry 的起始 offset（即 recv_offset_ 之后的第一个未填补位置）
// - out_size:   第一个 entry 的字节长度
// 返回 1 = 有 OOS gap（已写入 out_offset/out_size）；0 = 无 OOS gap
int linoh_stream_oos_first_gap(const linoh_stream_t *s,
                                uint64_t *out_offset,
                                size_t *out_size);

// OOS 累积阈值回调函数签名
// - first_gap_offset: 首个 OOS gap 的起始 offset
// - first_gap_size:   首个 OOS gap 的字节长度
// - oos_total_bytes:  OOS buffer 字节总数
// - user_data:        注册时传入的上下文指针
// 触发条件：Stream::recv case=3_inorder 退出时，若 OOS 累积 ≥ threshold_bytes 则同步调用。
// 注意：回调在 Stream::recv 内同步触发，调用方不应在回调内做阻塞操作。
typedef void (*linoh_on_oos_threshold_fn)(
    linoh_stream_t *s,
    uint64_t first_gap_offset,
    size_t first_gap_size,
    size_t oos_total_bytes,
    void *user_data);

// 注册 OOS 累积阈值回调
// - threshold_bytes=0 表示每次 OOS 累积都触发；>0 表示仅当 first_gap_size ≥ 阈值触发
// - 一个 Stream 同时仅支持一个回调；重复注册会覆盖
void linoh_stream_set_oos_callback(linoh_stream_t *s,
                                   linoh_on_oos_threshold_fn cb,
                                   void *user_data,
                                   size_t threshold_bytes);

// 清除 OOS 累积回调（注册 cb=NULL 等价于此函数）
void linoh_stream_clear_oos_callback(linoh_stream_t *s);

// ============================================================================
// v1.6.0.1 (P0+): EP（Expert Parallelism）C-API
//
// 包装 C++ EpChannel / EpSession / EpWorkerSession，让 win-worker / node-agent
// 通过 C 嵌入使用 EP 通道（MoE 专家并行）。
//
// 设计要点：
//   - EP 帧的可靠性（P6 重传/ACK）与接收回调绑在 EpChannel 上，
//     不能用裸 linoh_connection_t 发送（会绕过可靠性层）。
//   - linoh_ep_channel_t 内部持有 EpChannelAdapter（EpChannelIf 实现），
//     session 接管 channel 时转移所有权。
//   - 回调分两层：endpoint 级默认回调（新 channel 继承）+ channel 级精确覆盖。
//   - 回调内 payload 指针仅在回调期间有效，调用方需保留必须拷贝。
// ============================================================================

// --- EP 同步操作类型（对应 C++ EpSyncOp）---
typedef enum {
    LINOH_EP_SYNC_BARRIER   = 0,  // 屏障：所有 participant 到齐后释放
    LINOH_EP_SYNC_SIGNAL    = 1,  // 单向信号：worker 完成计算通知 master
    LINOH_EP_SYNC_ACK       = 2,  // 确认：对 signal 的应答
    LINOH_EP_SYNC_ALLREDUCE = 3,  // 全规约：跨 participant 聚合标量
    LINOH_EP_SYNC_RELEASE   = 4,  // 释放：master 广播解除阻塞
} linoh_ep_sync_op_t;

// --- EP AllReduce 规约操作（对应 C++ EpSyncFrame.reduce_op）---
enum {
    LINOH_EP_REDUCE_SUM = 0,
    LINOH_EP_REDUCE_MAX = 1,
    LINOH_EP_REDUCE_MIN = 2,
    LINOH_EP_REDUCE_AVG = 3,
};

// --- EP tensor 数据类型（对应 C++ TensorDType，用于 ShapeDescriptor）---
typedef enum {
    LINOH_EP_DTYPE_F32  = 0,
    LINOH_EP_DTYPE_F16  = 1,
    LINOH_EP_DTYPE_BF16 = 2,
} linoh_ep_dtype_t;

// --- EP 帧类型（对应 C++ EpFrameType，用于 frame_dropped 回调）---
enum {
    LINOH_EP_FRAME_DISPATCH = 0x20,
    LINOH_EP_FRAME_COMBINE  = 0x21,
    LINOH_EP_FRAME_SYNC     = 0x22,
};

// --- 不透明句柄 ---
typedef struct linoh_ep_channel        linoh_ep_channel_t;         // 包装 EpChannelAdapter
typedef struct linoh_ep_session        linoh_ep_session_t;         // 包装 EpSession（master 端）
typedef struct linoh_ep_worker_session linoh_ep_worker_session_t;  // 包装 EpWorkerSession（worker 端）

// --- EP 字节缓冲（用于 combine 输出，调用方负责 free .data）---
typedef struct {
    uint8_t *data;
    size_t   len;
} linoh_ep_bytes_t;

// 释放 linoh_ep_bytes_t 数组（dispatch 返回的 combines_out）
// combines: 数组首地址；cnt: 数组长度
void linoh_ep_bytes_free(linoh_ep_bytes_t *combines, size_t cnt);

// ============================================================================
// EP 回调函数签名
// ============================================================================

// 收到 EP_DISPATCH_FRAME
// padding 可能为空（padding_len=0）；payload 仅在回调期间有效
typedef void (*linoh_ep_on_dispatch_fn)(
    linoh_ep_channel_t *ch,
    uint64_t tensor_id, uint64_t expert_id, uint64_t token_cnt,
    const uint8_t *payload, size_t payload_len,
    const uint8_t *padding, size_t padding_len,
    void *user_data);

// 收到 EP_COMBINE_FRAME
typedef void (*linoh_ep_on_combine_fn)(
    linoh_ep_channel_t *ch,
    uint64_t tensor_id, uint64_t expert_id, uint64_t token_cnt,
    const uint8_t *payload, size_t payload_len,
    void *user_data);

// 收到 EP_SYNC_FRAME
typedef void (*linoh_ep_on_sync_fn)(
    linoh_ep_channel_t *ch,
    uint64_t sync_id, int sync_op, uint64_t participant_mask,
    uint8_t reduce_op,
    const uint8_t *payload, size_t payload_len,
    void *user_data);

// 帧达到最大重传次数被丢弃（worker 掉线 / 网络不可达）
// frame_type: LINOH_EP_FRAME_DISPATCH / COMBINE
typedef void (*linoh_ep_on_frame_dropped_fn)(
    linoh_ep_channel_t *ch,
    int frame_type, uint64_t frame_seq, uint64_t tensor_id,
    void *user_data);

// ============================================================================
// EP Channel API（单连接收发 + P6 可靠性）
// ============================================================================

// 从已有数据连接构造 EP channel
// data_conn: 通过 linoh_endpoint_connect_multimodal(..., LINOH_CHANNEL_EP_DISPATCH/COMBINE/SYNC)
//            或 linoh_endpoint_connect_with_alpn 建立的数据连接
// channel 内部持有 conn 的 shared_ptr 引用，conn 可先于 channel 释放
// 返回 NULL = 失败（conn 无效）
linoh_ep_channel_t *linoh_ep_channel_create(linoh_connection_t *data_conn);

// 释放 EP channel（会停止 recv/resend 循环）
// 注意：若 channel 已通过 linoh_ep_session_add_worker 或
//       linoh_ep_worker_session_set_channel 转移所有权给 session，
//       不得再调用此函数（由 session 统一释放）
void linoh_ep_channel_free(linoh_ep_channel_t *ch);

// 启动接收循环 + 重传检查循环（P6 可靠性）
// 必须在 send_* 和回调注册之后调用
// 返回 0=成功，负数=错误码
int linoh_ep_channel_start(linoh_ep_channel_t *ch);

// 停止接收循环 + 重传循环
void linoh_ep_channel_stop(linoh_ep_channel_t *ch);

// 是否在运行
int linoh_ep_channel_is_running(const linoh_ep_channel_t *ch);

// 发送 EP_DISPATCH_FRAME
// padding 可传 NULL/0 表示无对齐填充
// 返回 0=成功，负数=错误码
int linoh_ep_channel_send_dispatch(linoh_ep_channel_t *ch,
                                   uint64_t tensor_id, uint64_t expert_id,
                                   uint64_t token_cnt,
                                   const uint8_t *payload, size_t payload_len,
                                   const uint8_t *padding, size_t padding_len);

// 发送 EP_COMBINE_FRAME
int linoh_ep_channel_send_combine(linoh_ep_channel_t *ch,
                                  uint64_t tensor_id, uint64_t expert_id,
                                  uint64_t token_cnt,
                                  const uint8_t *payload, size_t payload_len);

// 发送 EP_SYNC_FRAME
// sync_op: LINOH_EP_SYNC_*；reduce_op: LINOH_EP_REDUCE_*（仅 ALLREDUCE 有效，其他传 0）
int linoh_ep_channel_send_sync(linoh_ep_channel_t *ch,
                               uint64_t sync_id, int sync_op,
                               uint64_t participant_mask,
                               uint8_t reduce_op,
                               const uint8_t *payload, size_t payload_len);

// --- channel 级回调注册（覆盖 endpoint 默认；传 NULL 清除）---
void linoh_ep_channel_on_dispatch(linoh_ep_channel_t *ch,
                                  linoh_ep_on_dispatch_fn cb, void *user_data);
void linoh_ep_channel_on_combine(linoh_ep_channel_t *ch,
                                 linoh_ep_on_combine_fn cb, void *user_data);
void linoh_ep_channel_on_sync(linoh_ep_channel_t *ch,
                              linoh_ep_on_sync_fn cb, void *user_data);
void linoh_ep_channel_on_frame_dropped(linoh_ep_channel_t *ch,
                                       linoh_ep_on_frame_dropped_fn cb, void *user_data);

// 获取 channel 统计（按需，返回 0=成功）
int linoh_ep_channel_stats(const linoh_ep_channel_t *ch,
                           uint64_t *dispatch_sent, uint64_t *combine_sent,
                           uint64_t *sync_sent, uint64_t *dispatch_recv,
                           uint64_t *combine_recv, uint64_t *sync_recv,
                           uint64_t *dispatch_resent, uint64_t *combine_resent,
                           uint64_t *ack_sent, uint64_t *ack_recv);

// ============================================================================
// endpoint 级 EP 默认回调（后续 linoh_ep_channel_create 自动继承）
// ============================================================================

void linoh_endpoint_on_ep_dispatch(linoh_endpoint_t *ep,
                                   linoh_ep_on_dispatch_fn cb, void *user_data);
void linoh_endpoint_on_ep_combine(linoh_endpoint_t *ep,
                                  linoh_ep_on_combine_fn cb, void *user_data);
void linoh_endpoint_on_ep_sync(linoh_endpoint_t *ep,
                               linoh_ep_on_sync_fn cb, void *user_data);
void linoh_endpoint_on_ep_frame_dropped(linoh_endpoint_t *ep,
                                        linoh_ep_on_frame_dropped_fn cb, void *user_data);

// ============================================================================
// EP Session API（master 端，包装 EpSession）
// ============================================================================
//
// master 端管理多 worker 连接池 + CommPlanner 规划 + dispatch 分发 + combine 收集 + barrier。
// dispatch() 阻塞直到所有 worker combine 回流（或超时降级）。

// EP 组配置（描述 EP 组拓扑 + 静态形状）
typedef struct {
    uint64_t master_node_id;          // EP-master 节点 ID
    // ep_workers + expert_placement 通过 linoh_ep_session_add_worker 逐步填充
    uint32_t num_experts;             // 总专家数
    uint32_t topk;                    // 每 token 选 top-k 专家（默认 1）
    // 静态形状
    int      dtype;                   // LINOH_EP_DTYPE_*
    uint32_t max_tokens;              // 最大 token 数（padding 到此值）
    uint32_t hidden_dim;              // hidden 维度
    uint32_t expert_count;            // 专家数（与 num_experts 通常一致）
    int      allow_partial_combine;   // 0=false，非 0=true（combine 超时降级）
} linoh_ep_session_config_t;

// 创建 EP session
linoh_ep_session_t *linoh_ep_session_create(const linoh_ep_session_config_t *cfg);

// 释放 EP session（会统一释放所有 add_worker 转移进来的 channel）
void linoh_ep_session_free(linoh_ep_session_t *sess);

// 添加 worker（channel 所有权转移给 session，转移后不得再用 ch 句柄）
// worker_node_id: worker 节点 ID
// expert_ids: 该 worker 承载的专家 ID 列表（expert_placement[worker_idx]）
// expert_cnt: expert_ids 数组长度
// 返回 0=成功，负数=错误码（含已存在相同 worker_node_id）
int linoh_ep_session_add_worker(linoh_ep_session_t *sess,
                                uint64_t worker_node_id,
                                linoh_ep_channel_t *ch,
                                const uint32_t *expert_ids, size_t expert_cnt);

// 移除 worker（会停止 channel 循环并释放）
int linoh_ep_session_remove_worker(linoh_ep_session_t *sess, uint64_t worker_node_id);

// 当前 worker 数量
size_t linoh_ep_session_worker_count(const linoh_ep_session_t *sess);

// 执行一次完整 dispatch → compute → combine → barrier 流程（阻塞）
//
// routing: 一维数组，routing[i * expert_cnt_per_token + j] = 第 i 个 token 的第 j 个目标专家 ID
// token_cnt: token 总数
// expert_cnt_per_token: 每个 token 的专家数（必须与 config.topk 一致）
// payload: 全部 token 的 embedding 拼接（size = token_cnt * hidden_dim * dtype_size）
// payload_len: payload 字节数
// timeout_ms: combine 等待超时（0 表示用默认 30s）
//
// combines_out: 接收 combine 数据缓冲区数组（按 worker_idx 顺序）
//               调用方负责用 linoh_ep_bytes_free 释放
// combines_cnt_out: 实际返回的 combine 数量
//
// 返回 0=成功（全部 combine 收齐 + barrier 成功），负数=错误码：
//   LINOH_ERR_PARAM: 参数无效
//   LINOH_ERR_INTERNAL: dispatch 失败 / combine 超时 / barrier 失败
int linoh_ep_session_dispatch(linoh_ep_session_t *sess,
                              const uint32_t *routing, size_t token_cnt,
                              size_t expert_cnt_per_token,
                              const uint8_t *payload, size_t payload_len,
                              uint64_t timeout_ms,
                              linoh_ep_bytes_t **combines_out,
                              size_t *combines_cnt_out);

// ============================================================================
// EP Worker Session API（worker 端，包装 EpWorkerSession）
// ============================================================================
//
// worker 端接收 dispatch → 触发 compute 回调 → 发送 combine。
// 持有单个 EpChannelIf（与 master 的连接）。

// compute 回调签名：业务层计算并返回结果字节流
// 返回值 linoh_ep_bytes_t：.data 由 linoh 内部 free（用 linoh_ep_compute_result_free），
//                          调用方必须用 malloc/new 分配 .data
typedef linoh_ep_bytes_t (*linoh_ep_compute_fn)(
    uint64_t tensor_id, uint64_t expert_id, uint64_t token_cnt,
    const uint8_t *payload, size_t payload_len,
    void *user_data);

// 释放 compute 回调返回的 bytes（linoh 内部调用，应用层一般不直接调）
void linoh_ep_compute_result_free(linoh_ep_bytes_t *r);

// 创建 worker session
linoh_ep_worker_session_t *linoh_ep_worker_session_create(uint64_t worker_node_id);

// 释放 worker session（会停止循环并释放转移进来的 channel）
void linoh_ep_worker_session_free(linoh_ep_worker_session_t *w);

// 设置 channel（所有权转移给 worker session，转移后不得再用 ch 句柄）
int linoh_ep_worker_session_set_channel(linoh_ep_worker_session_t *w,
                                        linoh_ep_channel_t *ch);

// 设置 compute 回调
int linoh_ep_worker_session_set_compute(linoh_ep_worker_session_t *w,
                                        linoh_ep_compute_fn cb, void *user_data);

// 启动 worker（启动接收循环 + 注册 dispatch 回调）
int linoh_ep_worker_session_start(linoh_ep_worker_session_t *w);

// 停止 worker
void linoh_ep_worker_session_stop(linoh_ep_worker_session_t *w);

// 是否在运行
int linoh_ep_worker_session_is_running(const linoh_ep_worker_session_t *w);

// ============================================================================
// V3-A: 跨域节点视图 C-API
//
// 为 orchestrator / 外部调度器提供跨域节点视图查询能力（纯数据查询，不含调度逻辑）。
// linoh 只暴露数据，调度决策由 orchestrator 自行完成。
//
// 设计要点：
//   - ControlPlane 是独立于 linoh_endpoint 的控制面组件，因此引入独立的不透明句柄
//     linoh_control_plane_t（与 linoh_endpoint_t 解耦，生命周期独立管理）。
//   - linoh_control_plane_from_cpp 从 C++ ControlPlane* 创建 C 句柄（非拥有，
//     底层 C++ 对象生命周期由调用方管理，C 句柄仅持有裸指针）。
//   - 跨域未启用（cross_domain_enabled=false）时，查询函数返回 0 / false，不报错。
// ============================================================================

// --- 不透明句柄（包装 C++ linoh::ControlPlane*，非拥有）---
typedef struct linoh_control_plane linoh_control_plane_t;

// --- 跨域节点视图条目（C 兼容结构，对应 C++ NodeRegistryEntry 跨域字段）---
// 逻辑数据 42 字节 + endpoint 32 字节 + 对齐填充
typedef struct linoh_cross_domain_node_view {
    uint32_t             domain_id;           ///< 节点所属域
    linoh_endpoint_id_t  endpoint;            ///< 节点 EndpointId（32 字节）
    float                overall_score;       ///< 综合评分 [0.0, 1.0]
    uint8_t              region;              ///< GeoRegion 枚举值（0=Unknown,1=North,...）
    uint8_t              state;               ///< NodeState 枚举值（0=Unknown,1=Online,2=Offline,...）
    uint8_t              is_cross_domain_rep; ///< 是否跨域代表（0=false, 1=true）
    uint8_t              reserved[3];         ///< 对齐填充
} linoh_cross_domain_node_view_t;

/// 从 C++ ControlPlane 指针创建 C 句柄（非拥有）
///
/// @param cpp_control_plane  C++ linoh::ControlPlane* 指针（以 void* 传递）
/// @return C 句柄；NULL 表示参数无效。用 linoh_control_plane_free 释放。
///
/// @note C 句柄仅持有裸指针，不拥有底层 C++ 对象。调用方必须确保 C++ 对象
///       在 C 句柄使用期间存活；linoh_control_plane_free 仅释放 C 包装层。
linoh_control_plane_t *linoh_control_plane_from_cpp(void *cpp_control_plane);

/// 释放 C 句柄（不释放底层 C++ ControlPlane 对象）
void linoh_control_plane_free(linoh_control_plane_t *cp);

/// 查询跨域节点视图
///
/// @param cp        linoh_control_plane_t 句柄
/// @param out_views 输出数组（调用方分配）
/// @param max_count out_views 数组容量
/// @return 实际填充的条目数（≤ max_count）；返回 0 表示无跨域节点或跨域未启用
///
/// 说明：
///   - 返回所有跨域节点（is_cross_domain=true）
///   - 不含本域节点
///   - 按 overall_score 降序排列
///   - 跨域未启用（cross_domain_enabled=false）时返回 0
int linoh_get_cross_domain_nodes(
    linoh_control_plane_t *cp,
    linoh_cross_domain_node_view_t *out_views,
    int max_count);

/// 查询跨域节点总数（用于预分配）
/// @return 跨域节点数；跨域未启用时返回 0
int linoh_get_cross_domain_node_count(linoh_control_plane_t *cp);

/// 查询本节点是否为跨域代表
/// @return 1=是跨域代表，0=否或跨域未启用
int linoh_is_cross_domain_rep(linoh_control_plane_t *cp);

// ============================================================================
// V3-B: 跨域数据面通道 C-API
//
// 为 win-worker / 第三方集成方提供跨域数据面连接能力。
// 包含跨域连接建立、骨干 Relay 设置、跨域连接统计查询、跨域 BBR 参数应用。
//
// 设计要点：
//   - 跨域连接复用既有 linoh_connection_t 句柄，新增 is_cross_domain 标记
//   - 跨域连接建立流程：地址解析（CrossDomainAddrHint/Pkarr DNS/Relay 兜底）
//     → ALPN 协商（pp-*/1）→ 数据连接建立 → BBR 跨域参数自适应
//   - 骨干 Relay 通过 linoh_set_cross_domain_backbone_relays 下发，
//     自动 pin + role=Backbone，跨域穿透优先选择
// ============================================================================

// --- 跨域连接统计（对应 C++ CrossDomainStats）---
typedef struct linoh_cross_domain_stats {
    uint64_t bytes_sent_cross_domain;     ///< 跨域发送字节（仅跨域连接累积）
    uint64_t bytes_received_cross_domain; ///< 跨域接收字节（仅跨域连接累积）
    uint32_t rtt_ms;                       ///< 跨域 RTT（毫秒，由 SRTT 推导）
    uint32_t peer_domain_id;               ///< 对端域 ID（跨域连接有效，本域为 0）
} linoh_cross_domain_stats_t;

// --- 跨域 BBR 参数配置（对应 C++ BbrCrossDomainConfig）---
typedef struct linoh_cross_domain_bbr_config {
    uint32_t cross_domain_min_rtt_window_sec;    ///< 跨域 min_rtt 窗口（秒，默认 30）
    uint32_t cross_domain_probe_rtt_interval_sec;///< 跨域 ProbeRTT 间隔（秒，默认 60）
    double   cross_domain_startup_gain;          ///< 跨域 startup 增益（默认 2.77）
    double   cross_domain_cwnd_gain;             ///< 跨域 cwnd 增益（默认 3.0）
    uint8_t  cross_domain_enable_pacing;         ///< 是否启用 pacing（0=false, 1=true）
    uint8_t  reserved[7];                        ///< 对齐填充
} linoh_cross_domain_bbr_config_t;

/// 建立跨域数据面连接
///
/// @param endpoint          linoh_endpoint_t 句柄
/// @param cp                linoh_control_plane_t 句柄（用于跨域地址解析）
/// @param peer_endpoint     对端跨域节点 EndpointId（32 字节）
/// @param peer_domain_id    对端域 ID
/// @param alpn              数据面 ALPN（如 "pp-hidden/1"，必须为 pp-*/1 系列）
/// @param out_conn          输出连接句柄（成功时填充）
/// @return 0=成功，<0=错误码（-1=参数错误，-2=地址解析失败，-3=连接建立失败）
///
/// 流程（V3-B 协议规范 §4.2）：
///   1. 调用 NodeRegistry::resolve_cross_domain_addr 解析对端地址
///      （机制 A: CrossDomainAddrHint 缓存 → B: Pkarr DNS → C: 兜底仅含 relays）
///   2. 建立 linoh Connection，标记 is_cross_domain=true + peer_domain_id
///   3. 协商 MTU（negotiate_cross_domain，默认 1500，不启用 jumbo）
///   4. 检测到首次 RTT > 50ms 时应用跨域 BBR 参数（自动调用）
int linoh_connect_cross_domain(
    linoh_endpoint_t *endpoint,
    linoh_control_plane_t *cp,
    const linoh_endpoint_id_t *peer_endpoint,
    uint32_t peer_domain_id,
    const char *alpn,
    linoh_connection_t **out_conn);

/// 设置跨域骨干 Relay 列表
///
/// @param cp           linoh_control_plane_t 句柄（通过 ControlPlane 转发到 RelayPool）
/// @param relay_urls   骨干 Relay URL 列表（字符串数组）
/// @param count        Relay URL 数量
/// @return 0=成功，<0=错误码
///
/// 说明：
///   - 自动设置 role=Backbone 并 pin（不可淘汰）
///   - 已存在的 URL 仅更新 role/pinned，不重复入池
///   - 由 orchestrator 在域代表启动时下发
///   - ControlPlane 需先通过 linoh_control_plane_set_relay_pool 注入 RelayPool
int linoh_set_cross_domain_backbone_relays(
    linoh_control_plane_t *cp,
    const char *const *relay_urls,
    int count);

/// 为 ControlPlane 注入 RelayPool 引用（用于跨域骨干 Relay 管理）
///
/// @param cp          linoh_control_plane_t 句柄
/// @param relay_pool  C++ nat::RelayPool* 指针（以 void* 传递，非拥有）
/// @return 0=成功，<0=错误码
///
/// @note ControlPlane 不拥有 RelayPool，调用方需确保 RelayPool 在 ControlPlane
///       使用期间存活。通常 RelayPool 由 Endpoint 持有，ControlPlane 仅持有引用。
int linoh_control_plane_set_relay_pool(
    linoh_control_plane_t *cp,
    void *relay_pool);

/// 查询跨域连接统计
///
/// @param conn       linoh_connection_t 句柄
/// @param out_stats  输出统计结构
/// @return 0=成功，<0=错误码（连接非跨域时返回 -1）
int linoh_get_cross_domain_conn_stats(
    linoh_connection_t *conn,
    linoh_cross_domain_stats_t *out_stats);

/// 应用跨域 BBR 参数到连接
///
/// @param conn      linoh_connection_t 句柄
/// @param config    跨域 BBR 参数配置
/// @return 0=成功，<0=错误码（连接拥塞控制器不支持跨域自适应时返回 -2）
///
/// 说明：
///   - 仅 BBR v2 控制器生效，NewReno 返回 -2
///   - 通常由 linoh_connect_cross_domain 内部在 RTT > 50ms 时自动调用
///   - 调用方也可手动调用覆盖默认参数
int linoh_apply_cross_domain_bbr_config(
    linoh_connection_t *conn,
    const linoh_cross_domain_bbr_config_t *config);

// ============================================================================
// v3.2.1 P1: Direct Return Path MASTER 端 C-API
//（自动降级 + return slot 管理 + 入站拦截）
//
// linoh_c 层独立的轻量 return slot 管理（与 C++ DirectReturnManager 平行）。
// 适用于纯 C-API MASTER 节点；node-agent（C++ API）可直接用 DirectReturnManager。
//
// 自动降级（P1 核心）：
//   - 直连路径：linoh_direct_return_enable_inbound 启用后，入站 pp-llm/1 stream 中的
//     ResultPP[DirectReturn] 被自动解析并路由到 return slot（不触发用户 on_stream_cb）。
//   - 逐跳路径：linoh_inject_hop_by_hop_result 将逐跳反向结果注入竞速。
//   - 两条路径竞争同一 slot，任一先到达即胜出，另一自然丢弃。
// ============================================================================

// 启用 pp-llm/1 入站 return stream 拦截（MASTER 端）
//
// 启用后，入站 pp-llm/1 stream 中的 ResultPP[DirectReturn] 会被自动解析并路由到
// return slot，不触发用户 on_stream_cb；其他消息仍走 on_stream_cb。
// 应在开始接受连接前调用。
//
// \return 0=成功，<0=错误
int linoh_direct_return_enable_inbound(linoh_endpoint_t *ep);

// 注册 return slot，预分配 stream_token（MASTER 端）
//
// \param ep     linoh_endpoint_t 句柄
// \param req_id PP 推理请求 ID
// \return stream_token（写入 ForwardPP.ReturnAddress），0=失败
//
// stream_token = fnv1a_64(req_id(8B,LE) || timestamp_ms(8B,LE)) 低 32 位
uint32_t linoh_register_return_slot(linoh_endpoint_t *ep, uint64_t req_id);

// 等待直连/逐跳竞速结果（MASTER 端，同步阻塞）
//
// \param ep         linoh_endpoint_t 句柄
// \param token      linoh_register_return_slot 返回的 token
// \param timeout_ms 超时（毫秒），0=非阻塞轮询
// \param out        结果输出缓冲区（可为 NULL，此时仅查询是否就绪）
// \param out_size   缓冲区容量（输入）
// \return >0=实际写入字节数，0=超时/取消/未就绪，<0=错误
int64_t linoh_await_return_result(linoh_endpoint_t *ep,
                                   uint32_t token,
                                   uint32_t timeout_ms,
                                   uint8_t *out,
                                   size_t out_size);

// 注入逐跳反向结果（P1 自动降级核心入口）
//
// 当 MASTER 通过 PP 反向链路收到逐跳反向 ResultPP 时调用，注入竞速。
// \param ep      linoh_endpoint_t 句柄
// \param req_id  PP 推理请求 ID（与 register 时一致）
// \param payload 逐跳反向 ResultPP 的 result 字节流
// \param len     payload 长度
// \return 1=逐跳反向胜出（注入成功），0=直连已胜出或 slot 不存在，<0=错误
int linoh_inject_hop_by_hop_result(linoh_endpoint_t *ep,
                                    uint64_t req_id,
                                    const uint8_t *payload,
                                    size_t len);

// 取消 return slot（推理取消或结果已到达时调用）
void linoh_cancel_return_slot(linoh_endpoint_t *ep, uint32_t token);

// Direct Return 统计（MASTER 端 return slot + 末节点端 return stream 合计）
typedef struct linoh_direct_return_stats {
    uint64_t return_streams_opened;     // open_return_stream 成功次数
    uint64_t return_streams_failed;     // open_return_stream 失败次数
    uint64_t results_sent_direct;       // send_result_direct 成功次数
    uint64_t results_received;          // 收到 RESULT 次数（直连+逐跳合计）
    uint64_t direct_return_won;         // 直连竞优胜出次数
    uint64_t hop_by_hop_won;            // 逐跳反向竞优胜出次数（自动降级成功）
    uint64_t fallback_invoked;          // inject_hop_by_hop_result 调用次数
    uint64_t return_slots_registered;   // register_return_slot 次数
    uint64_t return_slots_cancelled;    // cancel_return_slot 次数
    uint64_t pool_hits;                 // 连接池命中次数
    uint64_t pool_misses;               // 连接池未命中次数
} linoh_direct_return_stats_t;

// 查询 Direct Return 统计
// \return 0=成功，<0=错误
int linoh_direct_return_stats(linoh_endpoint_t *ep,
                               linoh_direct_return_stats_t *out);

// P2-1: 查询 Direct Return 统计（JSON 字符串，用于 orchestrator 监控上报）
//
// 将 return_streams_opened/failed、results_sent/received、direct_return_won、
// hop_by_hop_won、fallback_invoked、pool_hits/misses 等字段序列化为 JSON。
//
// \param ep       linoh_endpoint_t 句柄
// \param buf      输出缓冲区
// \param buf_size 缓冲区容量（建议 >= 512）
// \return >0=实际写入字节数（不含 NUL），0=无数据，<0=错误
int64_t linoh_direct_return_stats_json(linoh_endpoint_t *ep,
                                        char *buf, size_t buf_size);

// ============================================================================
// V3.5 P5-B SessionId C-API（UUID v4 会话标识）
//
// 对应 C++ linoh::protocol::SessionId。C 集成方（win-worker/node-agent）可
// 自行生成/管理推理会话 ID，再传给 C++ ApplicationApi/EP channel 关联推理请求。
// ============================================================================

/// SessionId 类型（16 字节 UUID v4，默认全零 = 未设置）
typedef struct {
    uint8_t bytes[16];  ///< UUID v4 字节（默认全零 = 未设置）
} linoh_session_id_t;

/// 生成随机 SessionId（UUID v4，基于 CSPRNG）
// @param out 输出 SessionId（CSPRNG 失败时填零）
// @return 0=成功，<0=错误码（LINOH_ERR_CRYPTO=CSPRNG 失败，LINOH_ERR_PARAM=NULL）
//
// @note 线程安全；CSPRNG 失败时 out 全零，调用方应检查 linoh_session_id_is_null
linoh_error_t linoh_session_id_generate(linoh_session_id_t *out);

/// 从 16 字节原始字节构造 SessionId
// @param data 输入字节流（长度 >= 16 取前 16B）
// @param len  输入长度
// @param out  输出 SessionId
// @return 0=成功，<0=LINOH_ERR_PARAM（data 为 NULL 或 len < 16）
linoh_error_t linoh_session_id_from_bytes(const uint8_t *data, size_t len,
                                           linoh_session_id_t *out);

/// 序列化 SessionId 到 16 字节缓冲
// @param sid     SessionId
// @param out     输出缓冲（容量 >= 16）
// @param out_cap 缓冲容量
// @return 实际写入字节数（16），0=失败（cap < 16 或 sid 为 NULL）
size_t linoh_session_id_to_bytes(const linoh_session_id_t *sid,
                                  uint8_t *out, size_t out_cap);

/// SessionId 转 UUID 字符串（8-4-4-4-12 小写十六进制，36 字符 + NUL）
// @param sid      SessionId
// @param buf      输出缓冲（容量 >= 37）
// @param buf_size 缓冲容量
// @return 实际写入字节数（含 NUL，37），0=失败
size_t linoh_session_id_to_string(const linoh_session_id_t *sid,
                                    char *buf, size_t buf_size);

/// 判断 SessionId 是否为零值（未设置）
// @return 1=零值（未设置），0=已设置，<0=参数错误
int linoh_session_id_is_null(const linoh_session_id_t *sid);

/// 比较两个 SessionId 是否相等
// @return 1=相等，0=不等，<0=参数错误
int linoh_session_id_equal(const linoh_session_id_t *a,
                            const linoh_session_id_t *b);

// ============================================================================
// V3.5 P5-B Compression C-API（zstd 按需压缩）
//
// 对应 C++ linoh::protocol::compress_payload / decompress_payload /
// recommend_compression。C 集成方可对大 payload 预压缩后再传给 C++ 层发送，
// 或接收方解压对端发来的压缩 payload。
// ============================================================================

/// 压缩算法枚举（对应 C++ CompressionAlgo）
typedef enum {
    LINOH_COMPRESS_NONE  = 0,  ///< 不压缩
    LINOH_COMPRESS_GZIP  = 1,  ///< Gzip（V3.5 暂未实现，返回 LINOH_ERR_PARAM）
    LINOH_COMPRESS_ZSTD  = 2,  ///< Zstd（V3.5 推荐，基于 vendored zstd 1.5.6）
} linoh_compression_algo_t;

/// 压缩 payload
// @param in       原始 payload
// @param in_len   原始长度
// @param algo     压缩算法（LINOH_COMPRESS_NONE 原样拷贝）
// @param level    压缩级别（zstd: 1-22，0=默认 3；gzip: 1-9）
// @param out      输出缓冲（调用方分配）
// @param out_cap  输出缓冲容量
// @param out_len  输出实际写入字节数
// @return 0=成功，<0=错误码（LINOH_ERR_PARAM=参数错误/算法未实现，
//         LINOH_ERR_INTERNAL=压缩失败/缓冲区不足）
//
// @note 空 payload 返回 0 + out_len=0
// @note zstd 压缩后无收益（>= 原始）时仍写入压缩结果（C 端自行判断是否使用）
// @note 建议分配 out_cap >= in_len + 64（zstd 最坏情况），避免缓冲不足
linoh_error_t linoh_compress_payload(const uint8_t *in, size_t in_len,
                                       int algo, int level,
                                       uint8_t *out, size_t out_cap,
                                       size_t *out_len);

/// 解压 payload
// @param in            压缩字节流
// @param in_len        压缩长度
// @param algo          压缩算法
// @param expected_size 预期解压大小（0=从 zstd 帧头自动解析）
// @param out           输出缓冲（调用方分配）
// @param out_cap       输出缓冲容量
// @param out_len       输出实际写入字节数
// @return 0=成功，<0=错误码
linoh_error_t linoh_decompress_payload(const uint8_t *in, size_t in_len,
                                         int algo, size_t expected_size,
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_len);

/// 自动推荐压缩算法（对应 C++ recommend_compression，O1 v2 规则）
// @param payload_size payload 字节数
// @param method_id    ApplicationMessage MethodId 枚举值（0x0010=ForwardPP 等）
// @param out_algo     输出推荐算法（LINOH_COMPRESS_* 枚举值）
// @return 0=成功，<0=错误码
//
// @note 推荐规则（O1 v2，按编码层优化方案判据）：
//   - Heartbeat(0x0004) / Tensor 分片族 / Observe / 认证帧 → 始终 None
//   - payload < 300B → None（流式压缩为负收益）
//   - ForwardPP(0x0010)/ResultPP(0x0011) → <1KB None，>=1KB Zstd
//   - 结构化控制面方法（Join/LoadModel/CrossDomain*/AddrInfoAnnounce 等）
//     → >=300B Zstd（1–16KB 为字典压缩主战场）
//   - 其他/未知 → <16KB None，>=16KB Zstd
linoh_error_t linoh_recommend_compression(size_t payload_size, int method_id,
                                            int *out_algo);

/// O1: 加载协议压缩字典（进程级，256 本轮换；发送端字典压缩的前提）
// @param dict_id 字典编号（写入 wire 首字节，0-255）
// @param dict    字典内容（zstd dictionary 格式，由 ZDICT_trainFromBuffer 训练）
// @param len     字典字节数（<=1MB）
// @return 0=成功，<0=错误码
linoh_error_t linoh_load_protocol_dict(uint8_t dict_id, const uint8_t *dict,
                                        size_t len);

/// O1: 开关消息自动压缩（进程级，默认 off；开启后 Connection 发送
// helper 按 recommend 规则自动压缩，字典优先、失败回退普通 zstd）
// @param enable 1=开启 0=关闭
// @param level  zstd 级别（1-22，0=默认 3）
// @return 0=成功，<0=错误码
//
// @note 部署顺序：两端先 linoh_load_protocol_dict 加载同一字典，再开压缩。
//       旧对端不支持字典压缩 flag（kCapZstdDict 协商联动为 O1.2），
//       混跑集群请先确认对端版本再开启。
linoh_error_t linoh_set_auto_compress(int enable, int level);

/// O1.3: 从文件加载协议压缩字典（路径版，部署侧便捷入口）
// @return 0=成功，<0=错误码
linoh_error_t linoh_load_protocol_dict_file(const char *path, uint8_t dict_id);

/// O1.3: 查询已注册字典信息（校验两端字典一致性）
// @param out_size  可空；字典字节数
// @param out_xxh64 可空；内容校验值（XXH64 种子 0）
// @return 0=已注册且信息有效；LINOH_ERR_PARAM=未注册
linoh_error_t linoh_protocol_dict_info(uint8_t dict_id, uint64_t *out_size,
                                        uint64_t *out_xxh64);

// ============================================================================
// O3: FEC 自适应控制器（不透明句柄；cluster 编码层优化方案 O3）
//
// 用法（LLMPP node-agent / 视频回传等 FEC 使用方）：
//   1. linoh_fec_adaptive_create 创建控制器
//   2. 周期（建议 1s）取 linoh 连接统计的 packets_sent/lost_packets
//      累计值喂 linoh_fec_adaptive_update
//   3. 用 linoh_fec_adaptive_current 的 M 档位重建/调整 FecGroup 配置
//      （RS K=16，block_size=1024 固定；档位 M∈{1,2,4} 对应 p<=0.5%/<=2%/>2%）
// ============================================================================

/// 创建 FEC 自适应控制器（返回不透明句柄，须 destroy 释放）
// @param out_handle 输出句柄（*handle 置为控制器指针）
// @return 0=成功，<0=错误码
linoh_error_t linoh_fec_adaptive_create(void **out_handle);

/// 喂入连接级累计统计（差分满窗口时评估一次；计数器回退自动重基线）
// @param handle        控制器句柄
// @param sent_total    累计发送包数（Connection 统计 packets_sent）
// @param lost_total    累计丢包数（Connection 统计 lost_packets）
// @param out_switched  可空；非空时输出本调用是否触发窗口评估（1/0）
// @return 0=成功，<0=错误码
linoh_error_t linoh_fec_adaptive_update(void *handle, uint64_t sent_total,
                                         uint64_t lost_total, int *out_switched);

/// 查询当前档位与平滑丢包率
// @param handle              控制器句柄
// @param out_recovery_blocks 输出当前 M（1/2/4；冷启动 2）
// @param out_loss_rate       可空；输出 EMA 丢包率（无样本 -1）
// @return 0=成功，<0=错误码
linoh_error_t linoh_fec_adaptive_current(void *handle, int *out_recovery_blocks,
                                          double *out_loss_rate);

/// 销毁控制器
linoh_error_t linoh_fec_adaptive_destroy(void *handle);

// ============================================================================
// v4.3.0 M7: 事件循环 select! 多路复用（C-API 不透明句柄）
//
// 提供 EventLoop + 3 个内置 EventSource（Shutdown/Linoh/Timer）的 C 接口。
// TaskQueue 为 C++ 模板，C 调用方请用自定义 EventSource 或直接用 C++ API。
//
// 典型用法：
//   linoh_event_loop_t* loop = linoh_event_loop_create();
//   linoh_event_source_t* sd = linoh_shutdown_event_create();
//   int sid = linoh_event_loop_register(loop, sd, 0);
//   while (running) {
//       int ids[8];
//       int n = linoh_event_loop_select(loop, ids, 8, 1000);
//       for (int i=0; i<n; ++i) { if (ids[i]==sid) running=0; }
//   }
// ============================================================================

/// 事件循环句柄（不透明）
typedef struct linoh_event_loop linoh_event_loop_t;
/// 事件源句柄（不透明）
typedef struct linoh_event_source linoh_event_source_t;

/// LinohEventSource 驱动模式
typedef enum {
    LINOH_EVENT_MODE_EXTERNAL = 0,  // 外部驱动：调用方手动 linoh_linoh_event_drive()
    LINOH_EVENT_MODE_SELF     = 1,  // 自驱动：内部线程自动 poll
} linoh_event_mode_t;

/// 创建事件循环
linoh_event_loop_t *linoh_event_loop_create(void);

/// 销毁事件循环（不销毁已注册的 source，需单独销毁）
void linoh_event_loop_destroy(linoh_event_loop_t *loop);

/// 注册事件源
/// @param priority 优先级（数字越小越优先）
/// @return source 索引（>=0），<0=失败
int linoh_event_loop_register(linoh_event_loop_t *loop,
                                linoh_event_source_t *src, int priority);

/// select! 等待任一 source 就绪
/// @param timeout_ms 超时（>0=等待毫秒数，0=非阻塞，<0=永久阻塞）
/// @param out_ids 输出就绪 source 索引数组
/// @param max_ids out_ids 容量
/// @return 就绪 source 数（<=max_ids），<0=错误
int linoh_event_loop_select(linoh_event_loop_t *loop, int *out_ids,
                              int max_ids, int timeout_ms);

/// 创建 ShutdownEvent（优雅退出）
linoh_event_source_t *linoh_shutdown_event_create(void);

/// 创建 LinohEventSource（linoh 网络事件）
/// @param ep linoh endpoint
/// @param mode 驱动模式
linoh_event_source_t *linoh_linoh_event_create(linoh_endpoint_t *ep,
                                                  linoh_event_mode_t mode);

/// 创建 TimerEvent（周期定时器）
/// @param period_ms 周期（毫秒）
linoh_event_source_t *linoh_timer_event_create(uint32_t period_ms);

/// 触发 ShutdownEvent
/// @return 0=成功，<0=错误
int linoh_shutdown_event_trigger(linoh_event_source_t *src);

/// 驱动 LinohEventSource（调用 linoh_endpoint_poll）
/// @return 事件数，<0=错误
int linoh_linoh_event_drive(linoh_event_source_t *src);

/// 启动 LinohEventSource 内部线程（SelfDriven 模式）
int linoh_linoh_event_start(linoh_event_source_t *src);

/// 停止 LinohEventSource 内部线程
int linoh_linoh_event_stop(linoh_event_source_t *src);

/// 重置 TimerEvent 周期起点
int linoh_timer_event_reset(linoh_event_source_t *src);

/// 销毁事件源
void linoh_event_source_destroy(linoh_event_source_t *src);

// ============================================================================
// v5.1.0 T-LA: Tensor 分片流水线 C-API（附录 A 计算通信重叠优化）
//
// 暴露 linoh::multimodal::TensorStreamer / TensorReassembler 的 C 绑定，
// 供 LLMPP node-agent 接入分片流水线（T-LA-001 上游分片异步发送 +
// T-LA-002 下游分片并发计算）。
//
// 设计要点：
//   - 不透明句柄 linoh_tensor_streamer_t / linoh_tensor_reassembler_t
//   - TensorStreamer 无状态（仅配置），shard() 可并发调用
//   - TensorReassembler 有状态（16 桶锁 + 回调），线程安全
//   - shard 序列化格式 = [48B TensorMeta 头][shard data]（与 C++ TensorShardMessage::serialize 一致）
//   - 内存所有权：shard 数据由 malloc 分配，由 linoh_tensor_shards_free 释放；
//     重组完成回调中的 data 由 malloc 分配，由 linoh_tensor_data_free 释放
// ============================================================================

/// Tensor 数据类型（对应 C++ linoh::multimodal::TensorDType）
typedef enum {
    LINOH_TENSOR_DTYPE_F32  = 0,  ///< float32
    LINOH_TENSOR_DTYPE_F16  = 1,  ///< float16
    LINOH_TENSOR_DTYPE_BF16 = 2,  ///< bfloat16
    LINOH_TENSOR_DTYPE_I32  = 3,  ///< int32
    LINOH_TENSOR_DTYPE_U8   = 4,  ///< uint8
    LINOH_TENSOR_DTYPE_F64  = 5,  ///< float64
    LINOH_TENSOR_DTYPE_I64  = 6,  ///< int64
    LINOH_TENSOR_DTYPE_I8   = 7,  ///< int8
} linoh_tensor_dtype_t;

/// TensorStreamer 句柄（发送端，无状态）
typedef struct linoh_tensor_streamer linoh_tensor_streamer_t;

/// TensorReassembler 句柄（接收端，有状态）
typedef struct linoh_tensor_reassembler linoh_tensor_reassembler_t;

/// shard 容器（POD，调用方负责通过 linoh_tensor_shards_free 释放 .data）
typedef struct {
    uint8_t *data;  ///< 序列化后的 shard 字节流（48B TensorMeta 头 + payload）
    size_t   len;   ///< 字节长度
} linoh_tensor_shard_t;

/// Tensor 重组完成回调
/// @param tensor_id   完成的 tensor ID
/// @param data        重组后的完整 tensor 数据（调用方负责 linoh_tensor_data_free）
/// @param len         数据长度
/// @param dtype       数据类型
/// @param shape       形状 [4]（0 表示无此维）
/// @param total_bytes 原始 tensor 字节数
/// @param user_data   用户数据
typedef void (*linoh_on_tensor_complete_fn)(
    uint64_t tensor_id,
    uint8_t *data, size_t len,
    linoh_tensor_dtype_t dtype,
    const uint32_t shape[4],
    uint64_t total_bytes,
    void *user_data);

/// Merkle 校验失败回调
/// @param tensor_id     校验失败的 tensor ID
/// @param expected_root 期望的 Merkle Root（32 字节）
/// @param actual_root   实际计算的 Merkle Root（32 字节）
/// @param user_data     用户数据
typedef void (*linoh_on_tensor_merkle_failure_fn)(
    uint64_t tensor_id,
    const uint8_t expected_root[32],
    const uint8_t actual_root[32],
    void *user_data);

/// chunk 校验失败回调（M17 逐 chunk sha256 校验）
/// @param tensor_id  校验失败的 tensor ID
/// @param shard_idx  校验失败的 shard 序号
/// @param chunk_idx  校验失败的 chunk 序号（0-based）
/// @param expected   期望的 chunk sha256（32 字节）
/// @param actual     实际计算的 chunk sha256（32 字节）
/// @param user_data  用户数据
typedef void (*linoh_on_tensor_chunk_failure_fn)(
    uint64_t tensor_id,
    uint32_t shard_idx,
    size_t chunk_idx,
    const uint8_t expected[32],
    const uint8_t actual[32],
    void *user_data);

// --- TensorStreamer API（发送端）---

/// 创建 TensorStreamer
/// @param shard_size       分片大小（字节，0=默认 64KB）
/// @param parallel_streams 并行 stream 数（0=默认 4，用于 assign_streams 轮询分配）
/// @return 非 NULL=成功，NULL=失败（参数无效）
linoh_tensor_streamer_t *linoh_tensor_streamer_create(size_t shard_size,
                                                       size_t parallel_streams);

/// 销毁 TensorStreamer
void linoh_tensor_streamer_free(linoh_tensor_streamer_t *s);

/// 查询分片大小
size_t linoh_tensor_streamer_shard_size(const linoh_tensor_streamer_t *s);

/// 查询并行 stream 数
size_t linoh_tensor_streamer_parallel_streams(const linoh_tensor_streamer_t *s);

/// 计算给定总字节数的分片数量
size_t linoh_tensor_streamer_shard_count(const linoh_tensor_streamer_t *s,
                                          size_t total_bytes);

/// 分片一个完整 tensor
/// @param s          streamer 句柄
/// @param tensor_id  唯一标识
/// @param data       原始 tensor 数据
/// @param data_len   数据长度
/// @param dtype      数据类型
/// @param shape      形状 [4]（0 表示无此维，可为 NULL=全 0）
/// @param shards_out 输出：分片数组（调用方负责 linoh_tensor_shards_free 释放）
/// @param count_out  输出：分片数量
/// @return 0=成功，<0=错误码
int linoh_tensor_streamer_shard(linoh_tensor_streamer_t *s,
                                 uint64_t tensor_id,
                                 const uint8_t *data, size_t data_len,
                                 linoh_tensor_dtype_t dtype,
                                 const uint32_t shape[4],
                                 linoh_tensor_shard_t **shards_out,
                                 size_t *count_out);

/// 释放分片数组（由 linoh_tensor_streamer_shard 返回的）
void linoh_tensor_shards_free(linoh_tensor_shard_t *shards, size_t count);

// --- TensorReassembler API（接收端）---

/// 创建 TensorReassembler
/// @return 非 NULL=成功，NULL=失败
linoh_tensor_reassembler_t *linoh_tensor_reassembler_create(void);

/// 销毁 TensorReassembler
void linoh_tensor_reassembler_free(linoh_tensor_reassembler_t *r);

/// 注册重组完成回调
void linoh_tensor_reassembler_on_complete(linoh_tensor_reassembler_t *r,
                                           linoh_on_tensor_complete_fn cb,
                                           void *user_data);

/// 注册 Merkle 校验失败回调
void linoh_tensor_reassembler_on_merkle_failure(linoh_tensor_reassembler_t *r,
                                                  linoh_on_tensor_merkle_failure_fn cb,
                                                  void *user_data);

/// 注册 chunk 校验失败回调
void linoh_tensor_reassembler_on_chunk_failure(linoh_tensor_reassembler_t *r,
                                                 linoh_on_tensor_chunk_failure_fn cb,
                                                 void *user_data);

/// 投递一个收到的 shard（序列化字节流）
/// @param r    reassembler 句柄
/// @param data shard 序列化字节流（48B TensorMeta 头 + payload）
/// @param len  字节长度
/// @return 1=新分片被接受，0=重复/无效，<0=错误
int linoh_tensor_reassembler_on_shard(linoh_tensor_reassembler_t *r,
                                       const uint8_t *data, size_t len);

/// 查询某个 tensor 的重组进度（0.0~1.0）
float linoh_tensor_reassembler_progress(const linoh_tensor_reassembler_t *r,
                                         uint64_t tensor_id);

/// 当前正在重组的 tensor 数量
size_t linoh_tensor_reassembler_pending_count(const linoh_tensor_reassembler_t *r);

/// 设置自动清理超时（秒，0=保持默认 60s）
void linoh_tensor_reassembler_set_auto_cleanup_timeout(linoh_tensor_reassembler_t *r,
                                                         size_t seconds);

/// 手动触发一次超时清理
/// @return 被清理的 tensor 数
size_t linoh_tensor_reassembler_run_auto_cleanup(linoh_tensor_reassembler_t *r);

/// 设置某个 tensor 的期望 Merkle Root（带外传递）
/// @param merkle_root 32 字节 Merkle Root，全零表示无需校验
void linoh_tensor_reassembler_set_expected_merkle_root(linoh_tensor_reassembler_t *r,
                                                         uint64_t tensor_id,
                                                         const uint8_t merkle_root[32]);

/// 启用/禁用 Merkle 校验（默认 0=禁用，向后兼容）
void linoh_tensor_reassembler_set_verify_merkle(linoh_tensor_reassembler_t *r,
                                                  int enable);

/// 启用/禁用逐 chunk 校验（默认 0=禁用，向后兼容）
void linoh_tensor_reassembler_set_verify_chunk_hashes(linoh_tensor_reassembler_t *r,
                                                        int enable);

/// 释放重组完成回调中返回的 tensor 数据
void linoh_tensor_data_free(uint8_t *data);

#ifdef __cplusplus
}  // extern "C"
#endif
