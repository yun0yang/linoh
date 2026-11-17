// session_deduper.hpp — V3.4 会话去重器（LRU 缓存近 N 个 SessionId）
//
// 借鉴 gpustack websocket_proxy/message.py 的 session_id 天然去重设计，
// linoh 用 LRU 控制内存（详见 docs/LINOH_EVENTBUS_BINARY_FRAME_IMPL_PLAN.md §3.3.3）。
//
// 使用场景：
//   - 接收方收到 HasSessionId 消息时，调用 check_and_record(sid)
//   - 返回 true（首次见到）→ 处理消息
//   - 返回 false（重复）→ 丢弃消息（防重放 / 防网络抖动重复投递）
//   - LRU 淘汰：容量超限时淘汰最旧记录，允许旧 SessionId 在淘汰后被重新接受
//
// 线程安全：所有接口加锁，可多线程并发调用。
// 容量：默认 4096（SessionId 16B × 4096 ≈ 64KB + unordered_set 开销）。
//
// 淘汰策略：FIFO（先进先出）。新 SessionId 加入尾部，容量超限时从头部淘汰。
//   - 不在重复命中时刷新 LRU 位置（防重放场景下，重复应被拒绝而非续命）
//   - deque 实现简单，O(1) push_back/pop_front；unordered_set O(1) 查找

#pragma once

#include <cstddef>
#include <deque>
#include <mutex>
#include <unordered_set>

#include "linoh/protocol/session_id.hpp"

namespace linoh::protocol {

/// 会话去重器（LRU/FIFO 缓存近 N 个 SessionId）
///
/// 设计要点：
///   - unordered_set<SessionId> 提供 O(1) 查找/插入
///   - deque<SessionId> 维护插入顺序，容量超限时从头部淘汰
///   - 所有接口加锁，线程安全
///   - check_and_record 返回 bool：true=首次（已记录），false=重复（已存在）
class SessionDeduper {
public:
    /// 构造指定容量的去重器
    /// @param capacity 最大缓存 SessionId 数量（默认 4096，约 64KB）
    explicit SessionDeduper(std::size_t capacity = 4096);

    /// 检查并记录 SessionId
    /// @return true=首次见到（已记录，调用方应处理消息）
    ///         false=重复（已存在，调用方应丢弃消息）
    /// @note 线程安全。容量超限时淘汰最旧记录。
    bool check_and_record(const SessionId &sid);

    /// 清空缓存
    void clear();

    /// 当前缓存的 SessionId 数量
    std::size_t size() const;

    /// 最大容量
    std::size_t capacity() const noexcept;

private:
    std::size_t capacity_;
    mutable std::mutex mtx_;
    std::unordered_set<SessionId> seen_;      // O(1) 查找
    std::deque<SessionId> lru_order_;         // FIFO 淘汰（头部最旧）
};

}  // namespace linoh::protocol
