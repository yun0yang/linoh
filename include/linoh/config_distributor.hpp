// config_distributor.hpp — 分布式配置分发器（v2.1 Phase 2）
//
// 基于控制面 v0 的 gossip 心跳传播机制，实现配置的分布式下发与热更新。
//
// 设计原则：
//   - 复用 NodeRegistry：落后检测复用注册表的节点状态
//   - Ed25519 签名：orchestrator 签名配置，节点验签后应用
//   - CRDT LWW 合并：同 key 以 version 更大者为准
//   - epoch 防回退：拒绝 to_epoch <= current_epoch 的 delta
//   - 订阅热更新：组件注册 key 前缀监听，配置变更后自动通知
//   - 历史回滚：保留最近 10 个快照，支持回滚到指定 epoch
//
// 传播流程（混合模式）：
//   orchestrator（签名+推送）→ 区域代表（验签+应用+gossip 传播）
//   → 邻居（验签+LWW 合并+继续传播）→ 全网收敛
//   区域代表检测落后节点（epoch 落后≥2）→ 主动推送全量快照

#pragma once

#include "linoh/base/key.hpp"           // base::EndpointId, base::PublicKey, base::SecretKey
#include "linoh/config_entry.hpp"        // ConfigEntry, ConfigSnapshot, ConfigDelta
#include "linoh/control_plane.hpp"       // NodeRegistry, ControlPlaneConfig, ClockFunc
#include "linoh/node_profile.hpp"        // TimePoint

#include <atomic>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace linoh {

// ============================================================================
// 配置变更回调
// ============================================================================

/// 配置变更回调类型（热更新通知）
/// @param key       变更的配置 key
/// @param old_value 旧值（空字符串表示新增）
/// @param new_value 新值（空字符串表示删除）
using ConfigChangeCallback = std::function<void(
    const std::string &key,
    const std::string &old_value,
    const std::string &new_value)>;

// ============================================================================
// ConfigDistributor — 配置分发器
// ============================================================================

/// 分布式配置分发器
///
/// 职责：
///   - 本地配置管理（set/get/snapshot）
///   - 配置同步（apply_snapshot/apply_delta，含签名验证）
///   - gossip 传播（build_delta_for/on_config_delta_received）
///   - 落后检测（lagging_nodes/update_node_config_epoch）
///   - 热更新订阅（subscribe/unsubscribe）
///   - 历史回滚（rollback_to/history_size）
///
/// 线程安全：全接口加锁，支持并发调用。
class ConfigDistributor {
public:
    ConfigDistributor(NodeRegistry &registry,
                     ControlPlaneConfig cfg,
                     ClockFunc clock = {});

    // 不可拷贝（含 mutex）
    ConfigDistributor(const ConfigDistributor &) = delete;
    ConfigDistributor &operator=(const ConfigDistributor &) = delete;

    // ------------------------------------------------------------------
    // 本地配置操作
    // ------------------------------------------------------------------

    /// 设置本地配置（仅 orchestrator 调用，会递增 epoch 并签名）
    /// @param key          配置 key（如 "control_plane.heartbeat_interval"）
    /// @param value        配置值（字符串形式）
    /// @param signing_key  Ed25519 私钥（用于签名）
    void set_local(const std::string &key, const std::string &value,
                   const base::SecretKey &signing_key);

    /// 删除本地配置（仅 orchestrator 调用）
    void delete_local(const std::string &key,
                      const base::SecretKey &signing_key);

    /// 查询本地配置值
    std::optional<std::string> get_local(const std::string &key) const;

    /// 获取全量快照（不含签名，本地读取用）
    ConfigSnapshot get_snapshot() const;

    /// 当前配置版本（epoch）
    std::uint64_t current_epoch() const noexcept;

    // ------------------------------------------------------------------
    // 配置同步（验证签名 + 应用 + 触发热更新）
    // ------------------------------------------------------------------

    /// 应用全量快照（验证签名 + 替换本地配置 + 触发热更新）
    /// @return 是否成功（签名验证失败或 epoch 回退返回 false）
    bool apply_snapshot(const ConfigSnapshot &snapshot,
                        const base::PublicKey &orchestrator_pubkey);

    /// 应用增量（验证签名 + LWW 合并 + 触发热更新）
    /// @return 是否成功
    bool apply_delta(const ConfigDelta &delta,
                     const base::PublicKey &orchestrator_pubkey);

    // ------------------------------------------------------------------
    // gossip 传播
    // ------------------------------------------------------------------

    /// 构建要传播给目标节点的配置增量
    /// 返回缓存的 delta（区域代表不签名，只转发 orchestrator 签名的 delta）
    /// @param target  目标节点 EndpointId
    /// @return nullopt 表示目标节点已是最新或无缓存 delta
    std::optional<ConfigDelta> build_delta_for(
        const base::EndpointId &target) const;

    /// 收到配置增量时的处理（邻居 gossip 传播）
    /// @param delta    配置增量
    /// @param source   发送者 EndpointId
    /// @param orchestrator_pubkey  orchestrator 公钥（验签用）
    void on_config_delta_received(const ConfigDelta &delta,
                                   const base::EndpointId &source,
                                   const base::PublicKey &orchestrator_pubkey);

    // ------------------------------------------------------------------
    // 落后检测
    // ------------------------------------------------------------------

    /// 返回配置版本落后超过指定 epoch 数的节点
    /// @param behind_epochs 落后阈值（默认 2）
    std::vector<base::EndpointId> lagging_nodes(
        std::uint64_t behind_epochs = 2) const;

    /// 更新节点的 config_epoch（从心跳中提取）
    void update_node_config_epoch(const base::EndpointId &node,
                                   std::uint64_t epoch);

    // ------------------------------------------------------------------
    // 订阅热更新
    // ------------------------------------------------------------------

    /// 订阅配置变更（按 key 前缀匹配）
    /// @param key_prefix  key 前缀（如 "control_plane.heartbeat"）
    /// @param cb          回调函数
    /// @return 订阅句柄（用于取消订阅）
    std::size_t subscribe(const std::string &key_prefix,
                          ConfigChangeCallback cb);

    /// 取消订阅
    void unsubscribe(std::size_t handle);

    // ------------------------------------------------------------------
    // 回滚
    // ------------------------------------------------------------------

    /// 回滚到指定 epoch（需要 orchestrator 签名）
    /// 回滚创建新的 epoch（不回退 epoch），将旧配置作为新版本下发
    /// @return 是否成功（epoch 不存在或签名失败返回 false）
    bool rollback_to(std::uint64_t epoch,
                     const base::SecretKey &signing_key);

    /// 可回滚的历史版本数
    std::size_t history_size() const noexcept;

private:
    NodeRegistry &registry_;
    ControlPlaneConfig config_;
    ClockFunc clock_;
    mutable std::mutex mu_;

    std::uint64_t epoch_{0};
    std::uint64_t version_counter_{0};  // 版本号计数器（orchestrator 侧）
    std::unordered_map<std::string, ConfigEntry> entries_;
    std::unordered_map<base::EndpointId, std::uint64_t> node_epochs_;

    // 订阅者列表（handle → (prefix, callback)）
    std::unordered_map<std::size_t,
                       std::pair<std::string, ConfigChangeCallback>> subscribers_;
    std::atomic<std::size_t> next_handle_{1};

    // 历史快照（用于回滚，保留最近 10 个）
    std::deque<ConfigSnapshot> history_;
    static constexpr std::size_t kMaxHistory = 10;

    // 缓存最近收到的 delta（含签名，用于区域代表转发给邻居）
    std::optional<ConfigDelta> cached_delta_;

    // 内部辅助
    void notify_subscribers(const std::string &key,
                            const std::string &old_val,
                            const std::string &new_val);
    void save_history_locked(const ConfigSnapshot &snapshot);
    bool verify_signature_locked(const std::vector<std::uint8_t> &data,
                                  const std::array<std::uint8_t, 64> &sig,
                                  const base::PublicKey &pubkey) const;
};

}  // namespace linoh
