// session_deduper.cpp — V3.4 SessionDeduper 实现
//
// check_and_record 使用 unordered_set::insert 的返回值判断首次/重复，
// 首次时同步加入 deque 尾部，容量超限时从头部淘汰对应 seen_ 记录。

#include "linoh/protocol/session_deduper.hpp"

namespace linoh::protocol {

SessionDeduper::SessionDeduper(std::size_t capacity) : capacity_(capacity) {}

bool SessionDeduper::check_and_record(const SessionId &sid) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto [it, inserted] = seen_.insert(sid);
    if (!inserted) {
        // 重复：已存在于 seen_，不更新 LRU 位置（防重放语义：见过即拒绝）
        return false;
    }
    // 首次：记录到 LRU 尾部
    lru_order_.push_back(sid);
    // 容量超限：从头部淘汰最旧
    while (lru_order_.size() > capacity_) {
        const auto &oldest = lru_order_.front();
        seen_.erase(oldest);
        lru_order_.pop_front();
    }
    return true;
}

void SessionDeduper::clear() {
    std::lock_guard<std::mutex> lk(mtx_);
    seen_.clear();
    lru_order_.clear();
}

std::size_t SessionDeduper::size() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return seen_.size();
}

std::size_t SessionDeduper::capacity() const noexcept {
    return capacity_;
}

}  // namespace linoh::protocol
