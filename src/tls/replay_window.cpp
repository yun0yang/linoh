// linoh/tls/replay_window.cpp — 0-RTT 重放保护窗口实现

#include "linoh/tls/replay_window.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <chrono>

namespace linoh::tls {

// ============================================================================
// 全局单例
// ============================================================================

ReplayWindow &ReplayWindow::instance() {
    static ReplayWindow inst;
    return inst;
}

// ============================================================================
// 时间工具
// ============================================================================

double ReplayWindow::now_ms_() {
    auto tp = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(
        tp.time_since_epoch());
    return ms.count();
}

// ============================================================================
// 核心逻辑
// ============================================================================

bool ReplayWindow::check_and_record(const base::PublicKey &peer,
                                     std::uint64_t pn,
                                     std::span<const std::uint8_t> payload_hash) {
    // 校验 hash 长度
    if (payload_hash.size() != kHashSize) {
        LINOH_WARN("ReplayWindow: invalid payload_hash size=", payload_hash.size());
        return false;  // 异常情况视为拒绝
    }

    std::array<std::uint8_t, kHashSize> hash_copy{};
    std::copy(payload_hash.begin(), payload_hash.end(), hash_copy.begin());

    std::lock_guard<std::mutex> lk(mu_);
    double now = now_ms_();

    auto &w = windows_[peer];
    evict_locked_(w, now);

    // tc-P1 (v1.7.0.8): 用 unordered_set O(1) 判重替代 O(N) 遍历 entries
    //   原 check_and_record 遍历 entries（最多 256 条）比较 (pn, hash)，
    //   高频 0-RTT 场景下（如推理数据 0-RTT 批量重放检测）成为瓶颈。
    //   fast_lookup 与 entries 同步维护（push_front → insert, pop_back → erase）。
    ReplayKey key{pn, hash_copy};
    if (w.fast_lookup.find(key) != w.fast_lookup.end()) {
        LINOH_WARN("ReplayWindow: replay detected, peer=", peer.fmt_short(),
                   " pn=", pn);
        return false;
    }

    // 记录新条目（插入头部）
    Entry e;
    e.pn = pn;
    e.payload_hash = hash_copy;
    e.timestamp_ms = now;
    w.entries.push_front(std::move(e));
    w.fast_lookup.insert(key);  // tc-P1: 同步插入快速查找集合

    // tc-L4 (v1.7.0.8): 修复容量裁剪逻辑。
    //   原代码 push_front 后用 resize(n) 裁剪，但 resize 对 deque 是"保留前 n 个"
    //   （保留最新），与 evict_locked_ 的"pop_back 最旧"语义一致但实现重复。
    //   初版修复直接删除了 resize，但 evict_locked_ 在 push_front 之前调用，
    //   只能保证 push_front 前 size <= N，push_front 后 size 可能 = N+1，
    //   导致 test_lru_eviction 用例失败（期望 size==N，实际 N+1）。
    //   正确做法：push_front 后若超容量，pop_back 一次淘汰最旧条目（与 evict 语义一致）。
    //   tc-P1: pop_back 时同步从 fast_lookup 删除对应 key。
    if (w.entries.size() > kMaxEntriesPerPeer) {
        const auto &back = w.entries.back();
        w.fast_lookup.erase(ReplayKey{back.pn, back.payload_hash});
        w.entries.pop_back();
    }

    LINOH_DEBUG("ReplayWindow: recorded 0-RTT, peer=", peer.fmt_short(),
                " pn=", pn, " entries=", w.entries.size());
    return true;
}

// ============================================================================
// 内部：懒清理过期 + 超容量记录
// ============================================================================

void ReplayWindow::evict_locked_(PerPeerWindow &w, double now_ms) {
    // 1. 清理过期（TTL）
    // tc-P1 (v1.7.0.8): pop_back 时同步从 fast_lookup 删除对应 key，保持一致
    while (!w.entries.empty()) {
        const auto &back = w.entries.back();
        if (now_ms - back.timestamp_ms > kTtlMs) {
            w.fast_lookup.erase(ReplayKey{back.pn, back.payload_hash});
            w.entries.pop_back();
        } else {
            break;
        }
    }

    // 2. 容量上限裁剪
    // tc-P1 (v1.7.0.8): 同步删除 fast_lookup 对应 key
    if (w.entries.size() > kMaxEntriesPerPeer) {
        // 从尾部（最旧）开始裁剪
        auto excess = w.entries.size() - kMaxEntriesPerPeer;
        for (std::size_t i = 0; i < excess && !w.entries.empty(); ++i) {
            const auto &back = w.entries.back();
            w.fast_lookup.erase(ReplayKey{back.pn, back.payload_hash});
            w.entries.pop_back();
        }
    }
}

// ============================================================================
// 维护接口
// ============================================================================

void ReplayWindow::gc() {
    std::lock_guard<std::mutex> lk(mu_);
    double now = now_ms_();
    for (auto &kv : windows_) {
        evict_locked_(kv.second, now);
    }
    // 清理空 peer 窗口
    for (auto it = windows_.begin(); it != windows_.end(); ) {
        if (it->second.entries.empty()) {
            it = windows_.erase(it);
        } else {
            ++it;
        }
    }
}

void ReplayWindow::clear() {
    std::lock_guard<std::mutex> lk(mu_);
    windows_.clear();
}

std::size_t ReplayWindow::peer_entry_count(const base::PublicKey &peer) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = windows_.find(peer);
    if (it == windows_.end()) return 0;
    return it->second.entries.size();
}

std::size_t ReplayWindow::peer_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return windows_.size();
}

} // namespace linoh::tls
