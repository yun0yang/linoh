// linoh/tls/replay_window.hpp — 0-RTT 重放保护窗口 (RFC 9001 §8 / TLS 1.3 §8)
//
// 0-RTT 数据本身不提供重放保护：攻击者可记录 0-RTT 密文并在稍后重放。
// 服务端必须实现重放检测。本类提供基于 (peer_pubkey + packet_number + payload_hash)
// 三元组的 LRU + TTL 检测窗口，跨连接共享（同一对端可能用不同 connection ID 重放）。
//
// 设计要点：
//   1. 全局单例：跨连接共享，避免同一 0-RTT 包被不同连接重复接受
//   2. 按 peer 分组：每个 peer 维护独立的窗口，避免相互干扰
//   3. LRU 淘汰：每 peer 窗口容量上限 kMaxEntriesPerPeer
//   4. TTL 过期：每条记录 kTtlMs 后失效，懒清理
//   5. 线程安全：mutex 保护所有读写

#pragma once

#include <linoh/base/key.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace linoh::tls {

/// 0-RTT 重放检测窗口
class ReplayWindow {
public:
    /// SHA-256 摘要长度
    static constexpr std::size_t kHashSize = 32;

    /// 每个对端最大记录数（LRU 上限）
    static constexpr std::size_t kMaxEntriesPerPeer = 256;

    /// 记录 TTL（毫秒）
    static constexpr double kTtlMs = 30000.0;

    /// 全局单例
    static ReplayWindow &instance();

    /// 检查并记录一个 0-RTT 包指纹
    ///
    /// @param peer 对端公钥（节点标识）
    /// @param pn 0-RTT 包编号
    /// @param payload_hash 明文 payload 的 SHA-256 摘要
    /// @return true=未重放（已记录）; false=重放（已存在）
    ///
    /// @note 调用前应已完成 AEAD 解密，确保 payload_hash 来自明文。
    ///       重放判断仅基于三元组匹配，与密文/连接 ID 无关。
    bool check_and_record(const base::PublicKey &peer,
                          std::uint64_t pn,
                          std::span<const std::uint8_t> payload_hash);

    /// 显式清理所有 peer 的过期记录（可选，正常情况下懒清理即可）
    void gc();

    /// 测试辅助：清空所有记录
    void clear();

    /// 测试辅助：返回某 peer 的记录数
    std::size_t peer_entry_count(const base::PublicKey &peer) const;

    /// 测试辅助：返回已记录的 peer 数量
    std::size_t peer_count() const;

private:
    ReplayWindow() = default;

    struct Entry {
        std::uint64_t pn;
        std::array<std::uint8_t, kHashSize> payload_hash;
        double timestamp_ms;
    };

    // tc-P1 (v1.7.0.8): 重放检测快速查找 key = (pn, payload_hash)
    //   原 check_and_record 遍历 entries (最多 256 条) 做 O(N) 重复检查，
    //   高频 0-RTT 场景下成为瓶颈。增加 unordered_set 做 O(1) 判重，
    //   list 仍维护 LRU 顺序（TTL 淘汰 / 容量裁剪从尾部 pop）。
    //   同步规则：entries push_front 时 set.insert，pop_back 时 set.erase。
    using ReplayKey = std::pair<std::uint64_t, std::array<std::uint8_t, kHashSize>>;

    struct ReplayKeyHash {
        std::size_t operator()(const ReplayKey &k) const noexcept {
            // pn 的 hash + payload_hash 的简单折叠
            std::size_t h = std::hash<std::uint64_t>{}(k.first);
            for (std::size_t i = 0; i < kHashSize; i += sizeof(std::size_t)) {
                std::size_t chunk = 0;
                for (std::size_t j = 0; j < sizeof(std::size_t) && i + j < kHashSize; ++j) {
                    chunk |= static_cast<std::size_t>(k.second[i + j]) << (j * 8);
                }
                h ^= chunk + 0x9e3779b9 + (h << 6) + (h >> 2);
            }
            return h;
        }
    };

    struct PerPeerWindow {
        std::list<Entry> entries;  // 头部最新，尾部最旧
        // tc-P1 (v1.7.0.8): 快速判重集合，与 entries 同步维护
        std::unordered_set<ReplayKey, ReplayKeyHash> fast_lookup;
    };

    mutable std::mutex mu_;
    std::unordered_map<base::PublicKey, PerPeerWindow> windows_;

    /// 内部：懒清理某 peer 的过期 + 超容量记录
    void evict_locked_(PerPeerWindow &w, double now_ms);

    /// 内部：当前时间（毫秒，相对值即可）
    static double now_ms_();
};

} // namespace linoh::tls
