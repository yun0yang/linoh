// control_plane.hpp — 轻量内置控制面（v2.0 Phase 1 交付物 7）
//
// linoh 自带节点注册/发现/分层心跳，降低 orchestrator 依赖。
// 万节点规模下心跳分层聚合（节点→邻居 gossip→区域代表→orchestrator），
// 避免心跳风暴发往 orchestrator。
//
// V3-A 扩展（v3.0 Phase 5 方向 A）：跨域控制面
//   - ControlPlaneConfig 新增跨域配置（cross_domain_enabled/domain_id/...）
//   - NodeRegistryEntry 新增跨域字段（domain_id/is_cross_domain/...）
//   - 新增 CrossDomainNodeDigest / CrossDomainDigestPayload 跨域摘要结构
//   - 新增 CrossDomainAggregator 跨域摘要聚合器
//   - ControlPlane 门面新增跨域接口（on_digest_received/get_cross_domain_view/...）
//   - 向后兼容：cross_domain_enabled=false（默认）时行为与 v2.3 一致
//
// 设计原则：
//   - 独立模块：不依赖 Endpoint 内部，仅复用 NodeProfile/GeoRegion/base 类型
//   - 注入式时钟：ClockFunc 可注入虚拟时钟，无需真实 sleep 即可测试时序逻辑
//   - 回调式传输：SendHeartbeatCallback 由上层注入，控制面不直接操作 QUIC
//   - 线程安全：NodeRegistry/HeartbeatAggregator/GossipDiscovery/CrossDomainAggregator 全接口加锁
//   - 向后兼容：ControlPlaneConfig.enabled 默认 false，关闭时行为与 v1.7.0.9 一致
//   - 职责边界：linoh 只做跨域数据采集/传播/查询，不做调度决策（归 orchestrator）
//
// 分层心跳架构：
//   orchestrator
//       ↑ 心跳聚合（每 30s，仅区域代表上报）
//   区域代表节点（每区域 1 个，由 stability_score 最高者担任）
//       ↑ 心跳聚合（每 10s）
//   城市内节点（每 5s gossip 心跳给 3 个邻居 + 区域代表）
//
// V3-A 跨域 gossip 架构（跨域启用时附加）：
//   邻域跨域代表 ←跨域摘要→ 本域跨域代表（每 30s，ttl=2）
//   本域跨域代表 = domain 内 stability_score 最高者

#pragma once

#include "linoh/base/key.hpp"            // base::EndpointId
#include "linoh/base/endpoint_addr.hpp"  // base::EndpointAddr, base::RelayUrl（V3-B 跨域地址缓存）
#include "linoh/config_entry.hpp"        // ConfigDelta, ConfigSnapshot (v2.1 Phase 2)
#include "linoh/node_profile.hpp"        // NodeProfile, NodeProfileStore, TimePoint
#include "linoh/geo_region.hpp"          // GeoRegion

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace linoh {

// V3-B 前向声明：避免与 address_lookup/lookup.hpp 循环包含。
// resolve_cross_domain_addr 仅用指针，前向声明足够，完整定义在 .cpp 中引用。
namespace address_lookup { class AddressLookup; }

// V3-B 前向声明：RelayPool 引用（仅指针，完整定义在 nat/relay_pool.hpp）
namespace nat { class RelayPool; }

// ============================================================================
// 节点在线状态
// ============================================================================

enum class NodeState : std::uint8_t {
    Unknown  = 0,  // 未探测
    Online   = 1,  // 在线
    Draining = 2,  // 排水中（即将下线）
    Offline  = 3,  // 离线
};

constexpr const char *node_state_name(NodeState s) noexcept {
    switch (s) {
        case NodeState::Unknown:  return "unknown";
        case NodeState::Online:   return "online";
        case NodeState::Draining: return "draining";
        case NodeState::Offline:  return "offline";
    }
    return "unknown";
}

// ============================================================================
// 节点事件（用于 subscribe_node_events 回调）
// ============================================================================

enum class NodeEventType : std::uint8_t {
    NodeJoined         = 0,  // 新节点上线
    NodeLeft           = 1,  // 节点主动离开
    NodeStale          = 2,  // 心跳超时（疑似下线）
    NodeUpdated        = 3,  // NodeProfile 更新
    RegionRepChanged   = 4,  // 区域代表变更
};

constexpr const char *node_event_type_name(NodeEventType t) noexcept {
    switch (t) {
        case NodeEventType::NodeJoined:       return "node_joined";
        case NodeEventType::NodeLeft:         return "node_left";
        case NodeEventType::NodeStale:        return "node_stale";
        case NodeEventType::NodeUpdated:      return "node_updated";
        case NodeEventType::RegionRepChanged: return "region_rep_changed";
    }
    return "unknown";
}

struct NodeEvent {
    NodeEventType type;
    base::EndpointId endpoint_id;
    GeoRegion region{GeoRegion::Unknown};
    TimePoint timestamp;
    std::string detail;  // 可选描述
};

// ============================================================================
// 节点注册表条目（NodeProfile + 控制面元数据）
// ============================================================================

struct NodeRegistryEntry {
    NodeProfile profile;
    NodeState state{NodeState::Unknown};
    TimePoint last_seen;            // 最后收到心跳时间
    TimePoint registered_at;        // 注册时间
    bool is_region_representative{false};
    std::vector<base::EndpointId> neighbors;  // 已知邻居列表

    // === V3-A: 跨域字段（默认值保证向后兼容） ===
    std::uint32_t domain_id{0};              // 节点所属域（0=本域/未指定）
    bool is_cross_domain{false};             // 是否跨域节点（非本域）
    bool is_cross_domain_rep{false};         // 是否跨域代表
    TimePoint digest_received_at;            // 跨域摘要最后接收时间（跨域节点用）
    float cached_overall_score{-1.0f};       // 跨域节点的 overall_score 缓存（-1=未设置，用 profile.overall_score()）

    /// 获取用于排序的 overall_score（跨域节点用 cached_overall_score，本域节点用 profile.overall_score()）
    float sort_score() const noexcept {
        return (is_cross_domain && cached_overall_score >= 0.0f)
                   ? cached_overall_score
                   : profile.overall_score();
    }
};

// ============================================================================
// 心跳载荷 v2（gossip piggyback 携带已知节点）
// ============================================================================

struct HeartbeatPayloadV2 {
    base::EndpointId sender_id;
    TimePoint timestamp;
    GeoRegion region{GeoRegion::Unknown};
    float stability_score{0.0f};    // 用于区域代表选举
    std::vector<base::EndpointId> known_nodes;  // piggyback 传播（gossip）
    std::uint64_t config_epoch{0};  // v2.1: 当前配置版本（用于落后检测）
};

// ============================================================================
// V3-A: 跨域节点摘要（42 字节逻辑数据，紧凑传输用）
// ============================================================================
//
// 跨域 gossip 传播的节点摘要，非全量 NodeProfile（节省跨域带宽）。
// 序列化时按固定字段顺序打包（domain_id|endpoint_id|overall_score|region|state），
// 不含填充字节，便于跨平台兼容。
//
// 字段布局（42 字节）：
//   domain_id      uint32        4 字节
//   endpoint_id    Ed25519 pubkey 32 字节
//   overall_score  float         4 字节
//   region         uint8         1 字节（GeoRegion 枚举）
//   state          uint8         1 字节（NodeState 枚举）
//   合计                         42 字节

struct CrossDomainNodeDigest {
    std::uint32_t domain_id{0};
    base::EndpointId endpoint_id{};
    float overall_score{0.0f};
    GeoRegion region{GeoRegion::Unknown};
    NodeState state{NodeState::Unknown};

    /// 序列化到字节缓冲（42 字节，固定布局）
    /// @return 实际写入字节数（42）
    static constexpr std::size_t kSerializedSize = 42;
    std::size_t serialize(std::uint8_t *out, std::size_t cap) const;

    /// 从字节缓冲反序列化
    /// @return 实际消费字节数（42），失败返回 0
    static std::size_t deserialize(const std::uint8_t *in, std::size_t len,
                                    CrossDomainNodeDigest &out);

    /// 简要描述（日志用）
    std::string brief() const;
};

// ============================================================================
// V3-A: 跨域摘要帧载荷
// ============================================================================
//
// 跨域代表间传播的摘要帧（通过 ctrl/1 ALPN 通道传输）。
// Ed25519 签名在帧层处理（由传输层签名/验签），不放入 payload 结构。
//
// 帧格式（详见 docs/V3_A_CROSS_DOMAIN_CONTROL.md §3.3）：
//   sender_domain_id (uint32)
//   node_count       (uint16)
//   ttl              (uint8)
//   reserved         (3 字节)
//   sender_endpoint_id (32 字节)
//   signature        (64 字节，Ed25519，覆盖帧头 + 全部摘要)
//   CrossDomainNodeDigest[node_count]（每个 42 字节，连续排列）

struct CrossDomainDigestPayload {
    std::uint32_t sender_domain_id{0};
    std::uint8_t ttl{2};                        // 传播跳数上限（默认 2）
    base::EndpointId sender_endpoint_id{};      // 发送方跨域代表 EndpointId
    std::vector<CrossDomainNodeDigest> nodes;   // 节点摘要数组

    /// 节点数上限校验（受 ControlPlaneConfig.max_digest_nodes 约束）
    bool within_limit(std::size_t max_digest_nodes) const noexcept;

    /// 简要描述（日志用）
    std::string brief() const;
};

// ============================================================================
// V3-B: 跨域节点地址提示帧载荷
// ============================================================================
//
// 跨域代表间传播的本域节点地址提示（通过 ctrl/1 ALPN 通道传输，与
// CrossDomainDigestPayload 并列）。CrossDomainDigest 只携带 EndpointId（42B
// 固定布局，序列化兼容性约束），无法直接发起数据面连接。AddrHint 在 Digest
// 之外附带本域高优节点的 EndpointAddr（relays + direct_addresses），供对端
// 缓存到 NodeRegistry 的 cross_domain_addr_cache_，跨域连接时免 DNS 解析。
//
// 帧格式（详见 docs/V3_B_CROSS_DOMAIN_DATA_PLANE.md §4.1.3）：
//   sender_domain_id   (uint32)        4 字节
//   hint_count         (uint8)         1 字节
//   ttl                (uint8)         1 字节
//   reserved           (3 字节)
//   sender_endpoint_id (Ed25519 pubkey) 32 字节
//   signature          (Ed25519, 64 字节，覆盖帧头 + 全部 AddrHintEntry)
//   AddrHintEntry[hint_count]（变长，复用 base::EndpointAddr 序列化）
//
// AddrHintEntry 序列化布局（变长）：
//   endpoint_id        (32 字节)
//   direct_addr_count  (uint8)
//   relay_url_count    (uint8)
//   direct_addrs[]     (TransportAddr 变长，长度前缀 host:port + 类型)
//   relay_urls[]       (RelayUrl 变长，长度前缀字符串)
//
// 约束：
//   - hint_count ≤ max_addr_hints（默认 10）
//   - 单帧总长 ≤ 4KB（跨域带宽约束）
//   - TTL 同 CrossDomainDigest（默认 2，防无限传播）
//   - Ed25519 签名覆盖帧头 + 全部 AddrHintEntry（私钥不出端）

struct CrossDomainAddrHintPayload {
    std::uint32_t sender_domain_id{0};
    std::uint8_t ttl{2};                        // 传播跳数上限（默认 2，与 DigestPayload 一致）
    base::EndpointId sender_endpoint_id{};      // 发送方跨域代表 EndpointId
    std::vector<base::EndpointAddr> hints;      // 本域高优节点地址提示列表

    /// 提示数上限校验（受 ControlPlaneConfig.max_addr_hints 约束）
    bool within_limit(std::size_t max_addr_hints) const noexcept;

    /// 简要描述（日志用）
    std::string brief() const;

    /// 序列化（不含签名，签名由传输层在帧头追加）
    /// @param out 输出缓冲区
    /// @param cap 缓冲区容量
    /// @return 实际写入字节数；0 = 失败（容量不足/数据非法）
    std::size_t serialize(std::uint8_t *out, std::size_t cap) const;

    /// 反序列化（不含签名验证，签名验证由传输层完成）
    /// @param in 输入字节流
    /// @param len 输入长度
    /// @param out_payload 输出载荷
    /// @return 实际消费字节数；0 = 失败（格式错误/超长）
    static std::size_t deserialize(const std::uint8_t *in, std::size_t len,
                                    CrossDomainAddrHintPayload &out_payload);
};

// ============================================================================
// 控制面配置
// ============================================================================

struct ControlPlaneConfig {
    /// 是否启用内置控制面（默认 false，向后兼容）
    bool enabled{false};

    /// 邻居 gossip 心跳间隔
    std::chrono::seconds heartbeat_interval{5};

    /// 区域代表聚合间隔
    std::chrono::seconds aggregate_interval{10};

    /// orchestrator 同步间隔
    std::chrono::seconds orchestrator_sync_interval{30};

    /// 心跳超时判定下线
    std::chrono::seconds stale_timeout{15};

    /// 每节点维护的邻居数上限
    std::size_t max_neighbors{5};

    /// 每轮 gossip 传播的邻居数
    std::size_t gossip_fanout{3};

    /// gossip piggyback 携带的节点数上限
    std::size_t max_known_nodes{100};

    // === V3-A: 跨域控制面配置 ===
    /// 是否启用跨域控制面（默认 false，向后兼容）
    /// enabled=false 时以下跨域配置全部忽略，行为与 v2.3 一致
    bool cross_domain_enabled{false};

    /// 本节点所属域（0=未指定，等价于跨域关闭）
    /// 由 orchestrator 分配，linoh 不决策域划分
    std::uint32_t domain_id{0};

    /// 跨域摘要聚合间隔（跨域代表发送摘要周期）
    std::chrono::seconds cross_domain_aggregate_interval{30};

    /// 跨域摘要传播 TTL（跳数上限，防止无限传播）
    std::uint8_t cross_domain_ttl{2};

    /// 单帧最大节点摘要数（受带宽约束，默认 50 节点 ≈ 2.1KB）
    std::size_t max_digest_nodes{50};

    /// 跨域节点超时清理间隔（digest_received_at 超时则清理）
    std::chrono::seconds cross_domain_stale_timeout{90};

    /// 邻域代表 EndpointId 列表（由 orchestrator 下发或配置注入）
    /// linoh 不决策与哪些域通信，仅使用此列表
    std::vector<base::EndpointId> peer_domain_reps;

    // === V3-B: 跨域数据面通道配置 ===
    /// 单帧 CrossDomainAddrHint 最大提示数（受带宽约束，默认 10 节点 ≈ 4KB）
    /// 每个 AddrHintEntry 含 EndpointId(32B) + 直连地址 + Relay URL，体积较大
    std::size_t max_addr_hints{10};

    /// 跨域地址缓存超时清理间隔（cached_at 超时则清理）
    /// 与 cross_domain_stale_timeout 解耦：AddrHint 缓存可能比 Digest 更频繁刷新
    std::chrono::seconds cross_domain_addr_cache_timeout{180};
};

// ============================================================================
// 回调类型定义
// ============================================================================

/// 传输回调（上层注入，控制面不直接操作 QUIC）
using SendHeartbeatCallback = std::function<void(
    const base::EndpointId &target,
    const HeartbeatPayloadV2 &payload)>;

/// 配置发送回调（v2.1: 向邻居推送 ConfigDelta）
using SendConfigCallback = std::function<void(
    const base::EndpointId &target,
    const ConfigDelta &delta)>;

/// V3-A: 跨域摘要发送回调（通过 ctrl/1 通道发送跨域摘要）
using SendDigestCallback = std::function<void(
    const base::EndpointId &target,
    const CrossDomainDigestPayload &payload)>;

/// V3-B: 跨域地址提示发送回调（通过 ctrl/1 通道发送 AddrHint）
/// 与 SendDigestCallback 并列，跨域代表在发送 Digest 后附带 AddrHint
using SendAddrHintCallback = std::function<void(
    const base::EndpointId &target,
    const CrossDomainAddrHintPayload &payload)>;

/// 节点事件回调
using NodeEventCallback = std::function<void(const NodeEvent &)>;

/// 时钟注入（测试用虚拟时钟）
using ClockFunc = std::function<TimePoint()>;

// ============================================================================
// NodeRegistry — 在线节点注册表
// ============================================================================

/// 线程安全的在线节点注册表
///
/// 扩展 NodeProfileStore，增加：
///   - 在线状态跟踪（Online/Draining/Offline）
///   - last_seen 心跳时间戳
///   - 区域代表选举
///   - 邻居关系维护
class NodeRegistry {
public:
    NodeRegistry() = default;
    explicit NodeRegistry(ClockFunc clock);

    // 不可拷贝（含 mutex）
    NodeRegistry(const NodeRegistry &) = delete;
    NodeRegistry &operator=(const NodeRegistry &) = delete;

    /// 注册/更新节点
    /// @return 是否为新注册（之前不存在）
    bool upsert(const NodeProfile &profile,
                NodeState state = NodeState::Online);

    /// 标记心跳到达（刷新 last_seen）
    /// @return 是否存在该节点
    bool touch(const base::EndpointId &id);

    /// 移除节点
    bool erase(const base::EndpointId &id);

    /// 查询
    std::optional<NodeRegistryEntry> get(const base::EndpointId &id) const;

    /// 全量快照
    std::vector<NodeRegistryEntry> snapshot() const;

    /// 当前条目数
    std::size_t size() const noexcept;

    /// 按区域筛选
    std::vector<NodeRegistryEntry> get_by_region(GeoRegion region) const;

    /// 检测并标记超时节点
    /// @param timeout 超时阈值（now - last_seen > timeout → 标记 Offline）
    /// @return 被标记为 Offline 的节点 EndpointId 列表
    std::vector<base::EndpointId> mark_stale(std::chrono::seconds timeout);

    /// 选举区域代表（stability_score 最高者）
    std::optional<base::EndpointId> elect_region_representative(GeoRegion region) const;

    /// 添加邻居关系（双向）
    void add_neighbor(const base::EndpointId &a, const base::EndpointId &b);

    /// 获取邻居列表
    std::vector<base::EndpointId> get_neighbors(const base::EndpointId &id) const;

    // === V3-A: 跨域接口 ===

    /// 批量 upsert 跨域节点摘要（来自跨域 gossip）
    /// @param digests 跨域节点摘要列表
    /// @param self_domain 本域 ID（用于标记 is_cross_domain）
    /// @return 新发现的节点数（之前不存在）
    std::size_t upsert_cross_domain_digests(
        const std::vector<CrossDomainNodeDigest> &digests,
        std::uint32_t self_domain);

    /// 按 domain 筛选节点
    std::vector<NodeRegistryEntry> get_by_domain(std::uint32_t domain_id) const;

    /// 查询所有跨域节点（is_cross_domain=true）
    /// @return 按 overall_score 降序排列
    std::vector<NodeRegistryEntry> get_cross_domain_nodes() const;

    /// 选举跨域代表（指定域内 stability_score 最高者）
    /// @param domain_id 目标域（仅在该域的节点中选举）
    /// @return 跨域代表 EndpointId；域内无节点返回 nullopt
    /// @note 平局时取 EndpointId 字典序最小者（确定性）
    std::optional<base::EndpointId> elect_cross_domain_rep(
        std::uint32_t domain_id) const;

    /// 标记本节点为跨域代表（由 ControlPlane 选举后调用）
    void set_cross_domain_rep(const base::EndpointId &id, bool is_rep);

    /// V3-A: 设置节点所属域（本节点启动时由 ControlPlane 调用）
    /// @param id 节点 EndpointId
    /// @param domain_id 域 ID
    /// @note 设置后 is_cross_domain=false（本节点不是跨域节点）
    void set_domain(const base::EndpointId &id, std::uint32_t domain_id);

    /// 清理过期的跨域节点（digest_received_at 超时）
    /// @param timeout 超时阈值（now - digest_received_at > timeout → 清理）
    /// @return 被清理的节点 EndpointId 列表
    /// @note 仅清理 is_cross_domain=true 的节点，本域节点不受影响
    std::vector<base::EndpointId> mark_cross_domain_stale(
        std::chrono::seconds timeout);

    // === V3-B: 跨域节点地址缓存接口 ===
    //
    // 独立于 entries_ 的缓存表，避免污染 NodeRegistryEntry 主结构（保持序列化兼容）。
    // 跨域代表收到 CrossDomainAddrHint 后调用 cache_cross_domain_addr 写入；
    // 跨域数据面连接建立前调用 resolve_cross_domain_addr 解析 EndpointAddr。

    /// 缓存跨域节点地址提示
    /// @param endpoint_id 跨域节点 EndpointId
    /// @param addr 跨域节点 EndpointAddr（relays + direct_addresses）
    /// @note 同一 EndpointId 多次缓存以最新为准（刷新 cached_at）
    void cache_cross_domain_addr(const base::EndpointId &endpoint_id,
                                 base::EndpointAddr addr);

    /// 查询跨域节点地址（仅查地址缓存，不做 DNS 兜底）
    /// @param endpoint_id 跨域节点 EndpointId
    /// @return 缓存的 EndpointAddr；未缓存返回 nullopt
    std::optional<base::EndpointAddr> get_cross_domain_addr(
        const base::EndpointId &endpoint_id) const;

    /// 查询跨域节点地址（含 Pkarr DNS 兜底）
    /// @param endpoint_id 跨域节点 EndpointId
    /// @param lookup Pkarr AddressLookup 实例（可为 nullptr，跳过 DNS）
    /// @return 解析到的 EndpointAddr
    /// @note 优先返回缓存，未缓存则通过 lookup 查询 DNS，全失败返回 nullopt
    std::optional<base::EndpointAddr> resolve_cross_domain_addr(
        const base::EndpointId &endpoint_id,
        address_lookup::AddressLookup *lookup) const;

    /// 清理过期的跨域地址缓存（与 mark_cross_domain_stale 协同）
    /// @param timeout 超时阈值（now - cached_at > timeout → 清理）
    /// @return 被清理的条目数
    std::size_t prune_cross_domain_addr_cache(std::chrono::seconds timeout);

    /// 跨域地址缓存条目数（诊断/测试用）
    std::size_t cross_domain_addr_cache_size() const noexcept;

private:
    mutable std::mutex mu_;
    ClockFunc clock_{[]() { return std::chrono::system_clock::now(); }};
    std::unordered_map<base::EndpointId, NodeRegistryEntry> entries_;

    // V3-B: 跨域节点地址缓存（独立于 entries_，避免污染 NodeRegistryEntry）
    // 独立 mutex 避免与 entries_ 读写互相阻塞（AddrHint 写入频繁但体积小）
    struct CrossDomainAddrEntry {
        base::EndpointAddr addr;
        TimePoint cached_at;
    };
    mutable std::mutex addr_cache_mu_;
    // V3-B: 缓存写回（DNS 解析结果回填）发生在 const 方法 resolve_cross_domain_addr 中，
    //       属"逻辑 const"模式（与 addr_cache_mu_ 一致），故标记 mutable。
    mutable std::unordered_map<base::EndpointId, CrossDomainAddrEntry> cross_domain_addr_cache_;
};

// ============================================================================
// HeartbeatAggregator — 分层心跳聚合
// ============================================================================

/// 分层心跳聚合器
///
/// 职责：
///   - 构建心跳载荷（含 gossip piggyback）
///   - 处理收到的心跳（更新注册表 + 传播 known_nodes）
///   - 选择 gossip 目标（随机 fanout 个邻居）
///   - 检测超时节点
class HeartbeatAggregator {
public:
    HeartbeatAggregator(NodeRegistry &registry,
                        ControlPlaneConfig cfg,
                        ClockFunc clock = {});

    /// 处理收到的心跳
    void on_heartbeat_received(const HeartbeatPayloadV2 &payload);

    /// 生成要发送的心跳（含 gossip piggyback）
    HeartbeatPayloadV2 build_heartbeat(const base::EndpointId &self_id,
                                       const NodeProfile &self_profile) const;

    /// 选择本轮 gossip 目标（随机 fanout 个邻居）
    std::vector<base::EndpointId> select_gossip_targets(
        const base::EndpointId &self_id) const;

    /// 检查超时节点并生成 NodeStale 事件
    std::vector<NodeEvent> check_stale();

    /// 统计：累计收到心跳数
    std::size_t heartbeats_received() const noexcept;

private:
    NodeRegistry &registry_;
    ControlPlaneConfig config_;
    ClockFunc clock_;
    mutable std::atomic<std::size_t> hb_received_{0};
};

// ============================================================================
// GossipDiscovery — 基于 gossip 的节点发现
// ============================================================================

/// 基于 gossip 的节点发现
///
/// 职责：
///   - 从心跳 piggyback 解析并注册新节点
///   - 发现节点（返回已知节点列表，按 score 降序）
///   - 构建下一轮 piggyback 列表（随机采样）
class GossipDiscovery {
public:
    GossipDiscovery(NodeRegistry &registry,
                    ControlPlaneConfig cfg,
                    ClockFunc clock = {});

    /// 处理 gossip 传播的节点信息
    void on_gossip_nodes(const std::vector<base::EndpointId> &known_nodes,
                         const base::EndpointId &source);

    /// 发现节点：返回已知节点列表（按 overall_score 降序，限 max_count 个）
    std::vector<base::EndpointId> discover(std::size_t max_count) const;

    /// 获取本节点应携带的 gossip piggyback 列表（随机采样）
    std::vector<base::EndpointId> build_piggyback(
        const base::EndpointId &self_id) const;

    /// 传播统计
    std::size_t gossip_rounds() const noexcept;

private:
    NodeRegistry &registry_;
    ControlPlaneConfig config_;
    ClockFunc clock_;
    mutable std::atomic<std::size_t> gossip_rounds_{0};
};

// ============================================================================
// V3-A: CrossDomainAggregator — 跨域摘要聚合器
// ============================================================================
//
// 职责与 HeartbeatAggregator 对应，但处理跨域摘要：
//   - 构造本域跨域摘要（从 registry 提取本域在线节点，限 max_digest_nodes）
//   - 处理收到的跨域摘要（验证签名后调用，注入 registry + 新发现计数）
//   - 判断是否应转发摘要（ttl > 1 且有邻域代表）
//   - 选择转发目标（邻域代表列表，排除来源域）
//   - 清理过期跨域节点（生成 NodeStale 事件）
//
// 设计原则：
//   - 不直接操作 QUIC，通过 SendDigestCallback 注入传输
//   - 不决策与哪些域通信，仅使用 config_.peer_domain_reps 列表
//   - 同域摘要不处理（避免环路）
//   - 纯数据采集与传播，不含任何调度决策

class CrossDomainAggregator {
public:
    CrossDomainAggregator(NodeRegistry &registry,
                          ControlPlaneConfig cfg,
                          ClockFunc clock = {});

    /// 构造本域跨域摘要
    /// @param self_id 本节点 EndpointId（作为 sender_endpoint_id）
    /// @param self_domain 本域 ID
    /// @return 跨域摘要帧载荷（未签名，签名由传输层处理）
    ///
    /// 行为：
    ///   - 从 registry 提取本域在线节点（domain_id == self_domain）
    ///   - 按 overall_score 降序取前 max_digest_nodes 个
    ///   - ttl = config_.cross_domain_ttl
    CrossDomainDigestPayload build_digest(
        const base::EndpointId &self_id,
        std::uint32_t self_domain) const;

    /// 处理收到的跨域摘要（验证签名后调用）
    /// @param payload 跨域摘要帧载荷
    /// @param self_domain 本域 ID
    /// @return 新发现的跨域节点数
    ///
    /// 行为：
    ///   - 同域摘要（sender_domain_id == self_domain）直接返回 0，不处理
    ///   - 跨域摘要：upsert 到 registry（标记 domain_id/is_cross_domain）
    ///   - 新节点触发 NodeJoined 事件（由 ControlPlane 统一 emit）
    std::size_t on_digest_received(const CrossDomainDigestPayload &payload,
                                    std::uint32_t self_domain);

    /// 判断是否应转发摘要
    /// @return ttl > 1 时返回 true
    bool should_forward(const CrossDomainDigestPayload &payload) const noexcept;

    /// 选择转发目标（邻域代表列表，排除来源域）
    /// @param payload 收到的摘要（用于判断来源域）
    /// @param peer_reps 邻域代表列表（通常为 config_.peer_domain_reps）
    /// @return 转发目标列表（已排除来源域代表）
    ///
    /// @note linoh 不决策与哪些域通信，仅从 peer_reps 中排除来源域
    std::vector<base::EndpointId> select_forward_targets(
        const CrossDomainDigestPayload &payload,
        const std::vector<base::EndpointId> &peer_reps) const;

    /// 清理过期跨域节点
    /// @return 被清理节点的 NodeStale 事件列表
    std::vector<NodeEvent> check_cross_domain_stale();

    /// 统计：累计收到的跨域摘要数
    std::size_t digests_received() const noexcept;

    /// 统计：累计转发的跨域摘要数
    std::size_t digests_forwarded() const noexcept;

private:
    NodeRegistry &registry_;
    ControlPlaneConfig config_;
    ClockFunc clock_;
    mutable std::atomic<std::size_t> digests_received_{0};
    mutable std::atomic<std::size_t> digests_forwarded_{0};
};

// ============================================================================
// ControlPlane — 统一门面
// ============================================================================

// 前向声明（避免循环包含）
class ConfigDistributor;

// V3.4: EventBus 前向声明
// event_bus.hpp 包含本文件（复用 NodeEvent/ClockFunc），反向包含会循环，
// 故本文件仅前向声明 EventBus/Subscriber/SubscriberConfig，完整定义在 .cpp 中引入。
class EventBus;
class Subscriber;
struct SubscriberConfig;

/// 轻量内置控制面
///
/// 用法：
///   ControlPlaneConfig cfg;
///   cfg.enabled = true;
///   ControlPlane cp(cfg);
///   cp.start(self_id, self_profile);
///   cp.set_send_callback([&](target, payload) { /* QUIC 发送 */ });
///   // 上层定时调用 cp.tick_once() 或由内部线程驱动
class ControlPlane {
public:
    ControlPlane();
    explicit ControlPlane(ControlPlaneConfig cfg, ClockFunc clock = {});

    // 不可拷贝
    ControlPlane(const ControlPlane &) = delete;
    ControlPlane &operator=(const ControlPlane &) = delete;

    // 析构函数声明在头文件，定义在 .cpp（ConfigDistributor 是前向声明，
    // unique_ptr 析构需要完整类型）
    ~ControlPlane();

    /// 启动控制面
    void start(const base::EndpointId &self_id,
               const NodeProfile &self_profile);

    /// 停止控制面
    void stop();

    /// 注册本节点（更新 NodeProfile）
    void register_node(const NodeProfile &profile);

    /// 发现节点
    std::vector<base::EndpointId> discover_nodes(std::size_t max_count = 5);

    /// 心跳驱动（由上层定时调用）
    /// 检查 heartbeat_interval → build + select targets + send_cb
    /// 检查 stale_timeout → 标记超时 + 触发事件
    /// v2.1: 区域代表检测落后节点并推送 ConfigDelta
    void tick_once();

    /// 订阅节点事件
    void subscribe_node_events(NodeEventCallback cb);

    // ========== V3.4: EventBus 集成 ==========

    /// 获取内部 EventBus（首次调用时懒初始化）
    /// @note EventBus 一旦创建持续到 ControlPlane 析构；
    ///       subscribe_node_events 也会触发初始化（内部桥接为 Subscriber）
    EventBus &event_bus();

    /// V3.4: 多订阅者订阅（返回 Subscriber 句柄，调用方自行 poll）
    /// 与旧 subscribe_node_events 并存，互不影响：
    ///   - 旧接口：单 callback，内部转为 EventBus 的一个 Subscriber + pump 线程
    ///   - 新接口：多订阅者，调用方持 shared_ptr<Subscriber> 自行 poll
    std::shared_ptr<Subscriber> subscribe_events(const SubscriberConfig &config);
    /// 便捷重载：默认配置订阅
    std::shared_ptr<Subscriber> subscribe_events();

    /// 与 orchestrator 同步（stub：返回本地注册表快照）
    std::vector<NodeRegistryEntry> sync_with_orchestrator() const;

    /// 收到心跳时调用（注入传输层回调）
    void on_heartbeat_received(const HeartbeatPayloadV2 &payload);

    /// 设置发送回调（控制面通过此回调发送心跳）
    void set_send_callback(SendHeartbeatCallback cb);

    // === v2.1 Phase 2: 配置分发接口 ===

    /// 获取配置分发器
    ConfigDistributor &distributor();
    const ConfigDistributor &distributor() const;

    /// 设置 orchestrator 公钥（用于验证配置签名）
    void set_orchestrator_pubkey(base::PublicKey pubkey);

    /// 设置配置发送回调（用于向邻居推送 ConfigDelta）
    void set_send_config_callback(SendConfigCallback cb);

    /// 收到配置增量时调用（从邻居 gossip 传播收到）
    void on_config_delta_received(const ConfigDelta &delta,
                                   const base::EndpointId &source);

    // === V3-A: 跨域控制面接口 ===

    /// 设置跨域摘要发送回调（通过 ctrl/1 通道发送跨域摘要）
    /// @note 跨域未启用时回调不调用，但可提前设置
    void set_send_digest_callback(SendDigestCallback cb);

    /// 收到跨域摘要时调用（从 ctrl/1 通道注入，已验签）
    /// @return 新发现的跨域节点数
    /// @note 跨域未启用时直接返回 0，不处理
    std::size_t on_digest_received(const CrossDomainDigestPayload &payload);

    /// 查询跨域节点视图（给 orchestrator 用，纯数据查询）
    /// @return 跨域节点列表（is_cross_domain=true），按 overall_score 降序
    ///
    /// @note linoh 只提供数据，不参与调度决策
    std::vector<NodeRegistryEntry> get_cross_domain_view() const;

    /// 是否为跨域代表
    /// @return 本节点是否为本域跨域代表
    /// @note 跨域未启用时返回 false
    bool is_cross_domain_rep() const noexcept;

    /// 获取跨域聚合器（测试/调试用）
    CrossDomainAggregator &cross_domain_aggregator();
    const CrossDomainAggregator &cross_domain_aggregator() const;

    // === V3-B: 跨域数据面通道接口 ===

    /// 设置跨域地址提示发送回调（通过 ctrl/1 通道发送 AddrHint）
    /// @note 跨域未启用时回调不调用，但可提前设置
    void set_send_addr_hint_callback(SendAddrHintCallback cb);

    /// 收到跨域地址提示时调用（从 ctrl/1 通道注入，已验签）
    /// @return 实际缓存到 registry 的条目数（同域提示 / 重复条目不计）
    /// @note 跨域未启用时直接返回 0，不处理
    std::size_t on_addr_hint_received(const CrossDomainAddrHintPayload &payload);

    /// 构造本域高优节点地址提示（跨域代表定期发送）
    /// @param self_id 本节点 EndpointId（作为 sender_endpoint_id）
    /// @param self_domain 本域 ID
    /// @return AddrHint 帧载荷（未签名，签名由传输层处理）
    ///
    /// 行为：
    ///   - 从 registry 提取本域在线节点（domain_id == self_domain）
    ///   - 按 overall_score 降序取前 max_addr_hints 个
    ///   - 每个节点附 EndpointAddr（relays + direct_addresses，由 Endpoint 注入）
    ///   - ttl = config_.cross_domain_ttl
    ///
    /// @note 节点 EndpointAddr 由 Endpoint::my_addr() 提供，ControlPlane 通过
    ///       set_local_addr_provider 注入回调获取（避免 ControlPlane 依赖 Endpoint）
    CrossDomainAddrHintPayload build_addr_hint(
        const base::EndpointId &self_id,
        std::uint32_t self_domain) const;

    /// 注入本节点 EndpointAddr 提供回调（用于 build_addr_hint 填充本域节点地址）
    /// @param cb 回调：传入 EndpointId，返回该节点的 EndpointAddr（无则 nullopt）
    /// @note 跨域代表本节点的地址由 Endpoint::my_addr() 提供；
    ///       本域其他节点的地址由本地 gossip 心跳 piggyback 携带（未来扩展）
    void set_local_addr_provider(
        std::function<std::optional<base::EndpointAddr>(const base::EndpointId &)> cb);

    // 配置/状态
    const ControlPlaneConfig &config() const { return config_; }
    NodeRegistry &registry() { return registry_; }
    const NodeRegistry &registry() const { return registry_; }
    bool is_running() const noexcept { return running_.load(); }

    // ===== V3-B: RelayPool 引用（跨域骨干 Relay 管理）=====
    /// 注入 RelayPool 引用（非拥有，由调用方管理生命周期）
    /// @note 通常 RelayPool 由 Endpoint 持有，ControlPlane 仅持有引用用于
    ///       跨域骨干 Relay 下发（linoh_set_cross_domain_backbone_relays 转发）
    void set_relay_pool(nat::RelayPool *pool) noexcept { relay_pool_ = pool; }

    /// 获取 RelayPool 引用（未注入时返回 nullptr）
    nat::RelayPool *relay_pool() noexcept { return relay_pool_; }
    const nat::RelayPool *relay_pool() const noexcept { return relay_pool_; }

private:
    ControlPlaneConfig config_;
    ClockFunc clock_;
    NodeRegistry registry_;
    std::unique_ptr<HeartbeatAggregator> aggregator_;
    std::unique_ptr<GossipDiscovery> discovery_;
    std::unique_ptr<ConfigDistributor> distributor_;  // v2.1: 配置分发器
    std::unique_ptr<CrossDomainAggregator> cross_domain_agg_;  // V3-A: 跨域聚合器
    base::EndpointId self_id_;
    NodeProfile self_profile_;
    std::atomic<bool> running_{false};
    std::atomic<bool> is_self_cross_domain_rep_{false};  // V3-A: 本节点是否为本域跨域代表
    TimePoint last_heartbeat_;
    TimePoint last_aggregate_;
    TimePoint last_orchestrator_sync_;
    TimePoint last_config_push_;  // v2.1: 上次配置推送时间
    TimePoint last_cross_domain_aggregate_;   // V3-A: 上次跨域摘要发送时间
    TimePoint last_cross_domain_stale_check_;  // V3-A: 上次跨域节点超时检查
    TimePoint last_cross_domain_addr_hint_;    // V3-B: 上次跨域地址提示发送时间
    TimePoint last_cross_domain_addr_prune_;   // V3-B: 上次跨域地址缓存清理时间
    NodeEventCallback event_cb_;
    SendHeartbeatCallback send_cb_;
    SendConfigCallback send_config_cb_;  // v2.1: 配置发送回调
    SendDigestCallback send_digest_cb_;  // V3-A: 跨域摘要发送回调
    SendAddrHintCallback send_addr_hint_cb_;  // V3-B: 跨域地址提示发送回调
    nat::RelayPool *relay_pool_{nullptr};     // V3-B: RelayPool 引用（非拥有，跨域骨干 Relay 管理）
    std::function<std::optional<base::EndpointAddr>(const base::EndpointId &)> addr_provider_;  // V3-B
    base::PublicKey orchestrator_pubkey_;  // v2.1: orchestrator 公钥
    mutable std::mutex mu_;

    // ========== V3.4: EventBus 懒初始化 ==========
    std::unique_ptr<EventBus> event_bus_;
    mutable std::mutex event_bus_mtx_;

    void emit_event(NodeEventType type,
                    const base::EndpointId &id,
                    const std::string &detail = "");

    // V3-A: 跨域 tick 逻辑（由 tick_once 调用）
    void tick_cross_domain_();

    // V3-B: 跨域地址提示 tick 逻辑（由 tick_cross_domain_ 调用）
    // 跨域代表在发送 Digest 后附带 AddrHint；定期清理地址缓存
    void tick_cross_domain_addr_hint_();
};

}  // namespace linoh
