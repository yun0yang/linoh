// config_entry.hpp — 分布式配置条目/快照/增量（v2.1 Phase 2）
//
// 定义配置下发的基础数据结构：
//   - ConfigEntry:   单个配置参数（key-value，CRDT LWW 语义）
//   - ConfigSnapshot: 全量配置快照（新节点加入/落后恢复用）
//   - ConfigDelta:    配置增量（gossip 传播用）
//
// 设计原则：
//   - 二进制紧凑序列化：复用 HeartbeatPayload 的小端序模式
//   - Ed25519 签名：防篡改，orchestrator 签名后节点验签
//   - CRDT LWW 合并：同 key 以 version 更大者为准
//   - epoch 单调递增：防回退保护
//
// 序列化布局：
//   ConfigEntry:   key_len(2) + key(N) + value_len(2) + value(M) + version(8) + timestamp_ms(8)
//   ConfigSnapshot: epoch(8) + created_at_ms(8) + origin(32) + entry_count(2) + entries(...) + signature(64)
//   ConfigDelta:   from_epoch(8) + to_epoch(8) + change_count(2) + changes(...) +
//                  deletion_count(2) + deletions(...) + signature(64)

#pragma once

#include "linoh/base/key.hpp"       // base::EndpointId, base::PublicKey, base::SecretKey, base::Signature
#include "linoh/node_profile.hpp"    // TimePoint

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace linoh {

// ============================================================================
// ConfigEntry — 单个配置参数
// ============================================================================

/// 配置条目（key-value，CRDT LWW 语义）
struct ConfigEntry {
    std::string key;              // "control_plane.heartbeat_interval"
    std::string value;            // "5"
    std::uint64_t version{0};     // 单调递增（orchestrator 分配，用于 LWW 合并）
    TimePoint updated_at;         // 更新时间戳

    /// 序列化为字节流
    std::vector<std::uint8_t> serialize() const;

    /// 从字节流解析
    /// @return 0 = 数据不足/格式错误；n = 成功消费 n 字节
    static std::size_t parse(std::span<const std::uint8_t> data, ConfigEntry &out);
};

// ============================================================================
// ConfigSnapshot — 全量配置快照
// ============================================================================

/// 全量配置快照（用于新节点加入或落后节点恢复）
struct ConfigSnapshot {
    std::uint64_t epoch{0};       // 全局纪元（每次配置变更递增）
    TimePoint created_at;         // 快照创建时间
    base::EndpointId origin;      // orchestrator 的 EndpointId
    std::vector<ConfigEntry> entries;  // 全部配置条目
    std::array<std::uint8_t, 64> signature{};  // Ed25519 签名（防篡改）

    /// 构造签名数据（用于验签：epoch + created_at + origin + entries 序列化）
    std::vector<std::uint8_t> signing_data() const;

    /// 序列化为字节流
    std::vector<std::uint8_t> serialize() const;

    /// 从字节流解析
    static std::size_t parse(std::span<const std::uint8_t> data, ConfigSnapshot &out);
};

// ============================================================================
// ConfigDelta — 配置增量
// ============================================================================

/// 配置增量（用于 gossip 传播）
struct ConfigDelta {
    std::uint64_t from_epoch{0};  // 旧纪元（0 表示全量同步）
    std::uint64_t to_epoch{0};    // 新纪元
    std::vector<ConfigEntry> changes;     // 变更的条目
    std::vector<std::string> deletions;   // 删除的 key
    std::array<std::uint8_t, 64> signature{};  // Ed25519 签名

    /// 是否为全量同步（from_epoch == 0）
    bool is_full() const noexcept { return from_epoch == 0; }

    /// 构造签名数据（用于验签：from_epoch + to_epoch + changes + deletions 序列化）
    std::vector<std::uint8_t> signing_data() const;

    /// 序列化为字节流
    std::vector<std::uint8_t> serialize() const;

    /// 从字节流解析
    static std::size_t parse(std::span<const std::uint8_t> data, ConfigDelta &out);
};

}  // namespace linoh
