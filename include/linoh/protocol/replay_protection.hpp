// replay_protection.hpp — v3.8.6 控制面指令 nonce + timestamp 防重放
//
// 设计来源：linoh 进化路线图 §6.2.3（H7 子任务）
//   - 控制面指令即使有 v3.8.5 Ed25519 签名信封，仍可被重放（签名验证不防重放）
//   - 本模块提供 NonceCache LRU + TTL 双重防重放 + timestamp 时钟偏移校验
//
// 防重放链路（与 v3.8.5 SignedMessage 配合）：
//   1. decode_and_verify(bytes)          — 先验签（防伪造）
//   2. 解析内层 data = {timestamp(8B) || nonce(32B) || payload}
//   3. replay.check(timestamp, nonce)    — 再查 nonce + 校验 timestamp（防重放）
//   4. 处理 payload
//
// 核心设计：
//   - NonceCache：std::list + std::unordered_map 实现 O(1) LRU
//     · 容量上限 10000（默认），超限淘汰最旧 nonce
//     · TTL 60s（默认），超时 nonce 自动失效（允许 60s 后重用）
//     · check_and_insert 原子操作（查重 + 过期清理 + 插入 + LRU 淘汰）
//     · shared_mutex 多读单写线程安全
//   - ReplayProtection：封装 NonceCache + timestamp 双向校验
//     · |now_unix - timestamp| > ttl → 丢弃（防旧指令重放 + 容忍时钟偏移）
//
// 时间源选择：
//   - NonceCache TTL 用 steady_clock（单调时钟，防系统时间跳变导致 nonce 提前/延后过期）
//   - timestamp 校验用 system_clock（Unix 时间戳，与控制面消息对齐）
//
// 应用范围（同 v3.8.5 SignedMessage）：
//   - ✅ ctrl/1 控制面消息（JOIN/FORWARD/RESULT 指令、心跳、状态）
//   - ❌ pp-hidden/1 数据面（hidden_state 逐跳转发，TTL 不适用）
//   - ❌ pp-img/1 / pp-video/1 / pp-audio/1（同上）
//
// 向后兼容：
//   - 可选工具模块，默认不启用，不修改现有控制面消息格式
//   - 调用方主动 check() 才生效；旧节点不调用时行为不变
//
// v3.8.6 范围：
//   1. NonceCache 类（LRU + TTL + 线程安全）
//   2. ReplayProtection 类（NonceCache + timestamp 校验）
//   3. Stats 统计结构（size/evicted/hits/duplicates）

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <unordered_map>

namespace linoh::protocol {

// ============================================================================
// 常量
// ============================================================================

/// nonce 字节长度（Ed25519 公钥同长度，32 字节）
constexpr std::size_t kNonceSize = 32;

/// 默认 LRU 缓存容量（最近 10000 个 nonce）
constexpr std::size_t kDefaultNonceCacheSize = 10000;

/// 默认 TTL（60 秒，超时 nonce 自动失效）
constexpr std::chrono::seconds kDefaultReplayTtl{60};

// ============================================================================
// NonceCache — LRU + TTL 双重防重放缓存
// ============================================================================

/// Nonce 防重放缓存（LRU + TTL）
///
/// 设计要点：
///   - std::list<NonceEntry> 维护 LRU 顺序（front=最新，back=最旧）
///   - std::unordered_map<NonceArray, ListIt> 提供 O(1) 查找
///   - TTL 过期：nonce 超过 ttl 未被重放则失效，允许 60s 后重用
///   - LRU 淘汰：容量超限时淘汰最旧 nonce（back），防内存无限增长
///   - check_and_insert 原子操作：查重 + 过期清理 + 插入 + 淘汰
///
/// 线程安全：shared_mutex 多读单写。
/// check_and_insert 用独占写锁（需修改 list + map）。
class NonceCache {
public:
    /// nonce 类型（32 字节定长数组）
    using NonceArray = std::array<std::uint8_t, kNonceSize>;

    /// 统计信息
    struct Stats {
        std::size_t size{0};          ///< 当前缓存条目数
        std::size_t evicted{0};       ///< 累计 LRU 淘汰数
        std::size_t expired{0};       ///< 累计 TTL 过期清理数
        std::size_t hits{0};          ///< 累计重复命中数（被拒绝）
        std::size_t accepts{0};       ///< 累计首次接受数（已插入）
    };

    /// 构造指定容量和 TTL 的 NonceCache
    ///
    /// @param max_size LRU 容量上限（默认 10000）
    /// @param ttl      nonce 生存时间（默认 60s，超时失效）
    explicit NonceCache(std::size_t max_size = kDefaultNonceCacheSize,
                         std::chrono::seconds ttl = kDefaultReplayTtl);

    /// 检查并插入 nonce（原子操作）
    ///
    /// @param nonce 32 字节 nonce
    /// @param now   单调时钟当前时刻（默认 steady_clock::now()，测试可注入）
    /// @return true  = 首次见到（已插入，调用方应处理指令）
    ///         false = 重复（未过期已存在，调用方应丢弃指令）
    ///
    /// @note 若 nonce 在缓存中但已过期（now - inserted_at > ttl），
    ///       视为首次（删除旧条目并重新插入，返回 true）。
    /// @note 容量超限时淘汰 list back（最旧），evicted 计数 +1。
    bool check_and_insert(std::span<const std::uint8_t> nonce,
                           std::chrono::steady_clock::time_point now =
                               std::chrono::steady_clock::now());

    /// 清理所有过期条目（可选定期调用，减少内存占用）
    ///
    /// @param now 单调时钟当前时刻
    /// @return 清理的条目数
    std::size_t evict_expired(std::chrono::steady_clock::time_point now =
                                  std::chrono::steady_clock::now());

    /// 当前缓存条目数
    std::size_t size() const;

    /// 最大容量
    std::size_t max_size() const noexcept;

    /// TTL（秒）
    std::chrono::seconds ttl() const noexcept;

    /// 统计信息快照
    Stats stats() const;

    /// 清空缓存（重置统计）
    void clear();

private:
    /// 缓存条目（nonce + 插入时刻）
    struct NonceEntry {
        NonceArray nonce{};
        std::chrono::steady_clock::time_point inserted_at;
    };

    using ListIt = std::list<NonceEntry>::iterator;

    /// std::array<uint8_t,32> 的哈希函数（FNV-1a 64-bit）
    struct NonceHash {
        std::size_t operator()(const NonceArray &n) const noexcept {
            std::uint64_t h = 14695981039346656037ULL;
            for (std::uint8_t b : n) {
                h ^= b;
                h *= 1099511628211ULL;
            }
            return static_cast<std::size_t>(h);
        }
    };

    std::size_t max_size_;
    std::chrono::seconds ttl_;
    mutable std::shared_mutex mutex_;
    std::list<NonceEntry> lru_order_;                                  // front=最新
    std::unordered_map<NonceArray, ListIt, NonceHash> cache_;          // nonce → list 迭代器
    mutable Stats stats_;                                              // 统计（mutable 便于 const 接口）
};

// ============================================================================
// ReplayProtection — NonceCache + timestamp 综合防重放
// ============================================================================

/// 控制面指令防重放保护（NonceCache + timestamp 双向校验）
///
/// 使用流程：
///   1. 从 v3.8.5 SignedMessage.decode_and_verify 提取内层 data
///   2. 解析 data = {timestamp(8B LE) || nonce(32B) || payload}
///   3. 调用 check(timestamp, nonce)
///   4. true → 处理 payload；false → 丢弃（重放或过期）
///
/// timestamp 校验：
///   - |now_unix - timestamp| > ttl → 丢弃
///   - 防旧指令重放（60s 前的指令拒绝）
///   - 防未来指令（时钟偏移过大拒绝）
class ReplayProtection {
public:
    /// 构造防重放保护器
    ///
    /// @param max_cache_size NonceCache 容量（默认 10000）
    /// @param ttl            防重放窗口（默认 60s，timestamp 和 nonce TTL 共用）
    explicit ReplayProtection(std::size_t max_cache_size = kDefaultNonceCacheSize,
                               std::chrono::seconds ttl = kDefaultReplayTtl);

    /// 综合校验控制面指令
    ///
    /// @param timestamp 指令的 Unix 时间戳（秒）
    /// @param nonce     32 字节随机 nonce
    /// @return true  = 通过（未重复 + timestamp 在窗口内）
    ///         false = 应丢弃（重复 nonce 或 timestamp 过期/未来）
    ///
    /// @note 校验顺序：
    ///   1. timestamp 双向校验（|now - timestamp| <= ttl）
    ///   2. nonce 查重（check_and_insert）
    ///   3. 仅当两者都通过才返回 true
    bool check(std::uint64_t timestamp,
               std::span<const std::uint8_t> nonce);

    /// NonceCache 统计信息（透传）
    NonceCache::Stats stats() const;

    /// 当前缓存条目数
    std::size_t size() const;

    /// 清空缓存
    void clear();

private:
    NonceCache nonce_cache_;
    std::chrono::seconds ttl_;
};

} // namespace linoh::protocol
