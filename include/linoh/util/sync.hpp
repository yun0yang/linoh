// sync.hpp — sync_t<T> 同步包装器（P5-C-1）
//
// 借鉴 Sunshine src/sync.h：
//   - 把"数据 + 锁"打包为一个单元，避免散落的 mutex 与 data 错配
//   - 提供异常安全的 with_lock(callable) 模式
//   - 支持 shared_mutex 的 shared_lock 多读单写
//
// 设计要点：
//   1. copy/move 构造使用 std::lock(lhs.mutex, rhs.mutex) 同时上锁避免死锁
//   2. copy/move 赋值被禁用（需要显式 lock 后操作，避免遗忘加锁）
//   3. lock() 返回 std::unique_lock<M>，比 lock_guard 更灵活（可 unlock/move）
//   4. with_lock(callable) 是异常安全的 RAII 模式，推荐使用
//   5. operator*/operator-> 仅在已持有锁时使用（debug 模式下可加断言）

#pragma once

#include <concepts>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <type_traits>
#include <utility>

namespace linoh::util {

/// @brief 同步包装器：把数据与保护它的锁绑定为一个单元
///
/// 用法示例：
/// @code
///   sync_t<std::vector<int>> vec;
///
///   // 方式 1：with_lock（推荐，异常安全）
///   vec.with_lock([](std::vector<int>& v) {
///       v.push_back(42);
///   });
///
///   // 方式 2：手动 lock
///   auto lk = vec.lock();
///   lk->push_back(42);  // operator-> 返回 T*
///
///   // 方式 3：shared_lock（仅 shared_mutex）
///   sync_t<std::string, std::shared_mutex> s;
///   s.with_shared([](const std::string& v) {
///       std::cout << v;
///   });
/// @endcode
///
/// @tparam T 数据类型
/// @tparam M mutex 类型（默认 std::mutex，可换 std::shared_mutex）
template <class T, class M = std::mutex>
class sync_t {
public:
    using value_t = T;
    using mutex_t = M;

    /// 默认构造（T 必须可默认构造）
    sync_t() = default;

    /// 从值构造
    explicit sync_t(T val) : raw_(std::move(val)) {}

    // ------------------------------------------------------------------
    // 拷贝/移动构造：使用 std::lock 同时锁住两个 mutex 避免死锁
    // ------------------------------------------------------------------
    sync_t(const sync_t& other) {
        std::lock(other.mutex_, mutex_);
        raw_ = other.raw_;
        mutex_.unlock();
        other.mutex_.unlock();
    }

    sync_t(sync_t&& other) {
        std::lock(other.mutex_, mutex_);
        raw_ = std::move(other.raw_);
        mutex_.unlock();
        other.mutex_.unlock();
    }

    // 显式禁用拷贝/移动赋值：避免在未加锁状态下被误用
    sync_t& operator=(const sync_t&) = delete;
    sync_t& operator=(sync_t&&) = delete;

    // ------------------------------------------------------------------
    // 锁操作
    // ------------------------------------------------------------------

    /// 获取独占锁（写锁），返回 unique_lock 提供 operator->/operator*
    /// @return std::unique_lock<M>，可直接 -> 访问 raw_
    std::unique_lock<M> lock() {
        return std::unique_lock<M>(mutex_);
    }

    /// 获取共享锁（仅 shared_mutex 特化）
    /// @return std::shared_lock<M>
    template <class U = M, typename = std::enable_if_t<std::is_same_v<U, std::shared_mutex>>>
    std::shared_lock<M> shared_lock() {
        return std::shared_lock<M>(mutex_);
    }

    // ------------------------------------------------------------------
    // with_lock / with_shared：异常安全的 callable 模式
    // ------------------------------------------------------------------

    /// @brief 在持有锁的状态下执行 callable
    /// @tparam F callable 类型：void(T&) 或 R(T&)
    /// @return callable 的返回值（若非 void）
    template <class F>
    auto with_lock(F&& f) -> decltype(std::forward<F>(f)(std::declval<T&>())) {
        std::lock_guard<M> lk(mutex_);
        return std::forward<F>(f)(raw_);
    }

    /// @brief 在持有共享锁的状态下执行 callable（仅 shared_mutex）
    template <class F>
    auto with_shared(F&& f) const
        -> std::enable_if_t<std::is_same_v<M, std::shared_mutex>,
                            decltype(std::forward<F>(f)(std::declval<const T&>()))> {
        std::shared_lock<M> lk(mutex_);
        return std::forward<F>(f)(raw_);
    }

    // ------------------------------------------------------------------
    // 直接访问（必须已持有锁，否则 UB）
    // ------------------------------------------------------------------
    T& operator*() { return raw_; }
    const T& operator*() const { return raw_; }
    T* operator->() { return &raw_; }
    const T* operator->() const { return &raw_; }

    /// 仅用于测试/调试：返回当前是否无锁（best-effort，不可靠）
    /// 注意：std::mutex::try_lock 在已锁时返回 false，但仅用于调试
    bool debug_is_uncontended() const {
        if constexpr (std::is_same_v<M, std::mutex>) {
            bool got = const_cast<M&>(mutex_).try_lock();
            if (got) {
                const_cast<M&>(mutex_).unlock();
                return true;
            }
            return false;
        }
        return false;
    }

private:
    T raw_{};
    mutable M mutex_;

    // 友元：lock_pair 需要直接访问 mutex_ 做 std::lock(a, b) 避免死锁
    template <class T1, class M1, class T2, class M2>
    friend std::pair<std::unique_lock<M1>, std::unique_lock<M2>>
    lock_pair(sync_t<T1, M1>& a, sync_t<T2, M2>& b);
};

/// @brief sync_t 的 std::shared_mutex 特化别名
template <class T>
using shared_sync_t = sync_t<T, std::shared_mutex>;

// --------------------------------------------------------------------------
// 辅助：lock multiple sync_t 同时上锁（避免死锁）
// --------------------------------------------------------------------------

/// @brief 同时锁住两个 sync_t（使用 std::lock 避免死锁）
/// @return 一对 unique_lock（已持有锁）
template <class T1, class M1, class T2, class M2>
std::pair<std::unique_lock<M1>, std::unique_lock<M2>> lock_pair(sync_t<T1, M1>& a,
                                                                sync_t<T2, M2>& b) {
    std::lock(a.mutex_, b.mutex_);  // 同时上锁避免死锁
    return {std::unique_lock<M1>(a.mutex_, std::adopt_lock),
            std::unique_lock<M2>(b.mutex_, std::adopt_lock)};
}

}  // namespace linoh::util
