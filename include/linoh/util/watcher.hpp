#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace linoh::util {

/// 可订阅的值变化通知：`Watcher<T>` 保存当前值，并允许调用者
/// 通过 `get()` 立即读取，或通过 `next()` 等待下一次变化。
///
/// 对应 iroh 中 `n0_watcher::Watcher`，设计为线程安全。
template <typename T>
class Watcher {
public:
    Watcher() = default;
    explicit Watcher(T initial) : value_{std::move(initial)}, version_{1} {}

    /// 原子地更新值，唤醒所有 `next()` 等待者。
    void set(T v) {
        {
            std::lock_guard lk(mu_);
            value_ = std::move(v);
            ++version_;
        }
        cv_.notify_all();
    }

    /// 若值已存在则更新，否则初始化。
    template <typename F>
    void update(F &&fn) {
        {
            std::lock_guard lk(mu_);
            if (value_.has_value()) {
                *value_ = std::invoke(std::forward<F>(fn), *value_);
            } else {
                value_ = std::invoke(std::forward<F>(fn), std::nullopt);
            }
            ++version_;
        }
        cv_.notify_all();
    }

    /// 非阻塞读取。
    std::optional<T> peek() const {
        std::lock_guard lk(mu_);
        return value_;
    }

    /// 阻塞读取（直到值存在）。
    T get() const {
        std::unique_lock lk(mu_);
        cv_.wait(lk, [this] { return value_.has_value(); });
        return *value_;
    }

    /// 阻塞等待"相对于 baseline 的下一次更新"。
    T next(std::size_t baseline_version = 0) const {
        std::unique_lock lk(mu_);
        cv_.wait(lk, [this, baseline_version] {
            return value_.has_value() && version_ > baseline_version;
        });
        return *value_;
    }

    std::size_t version() const {
        std::lock_guard lk(mu_);
        return version_;
    }

private:
    mutable std::mutex mu_;
    mutable std::condition_variable cv_;
    std::optional<T> value_;
    std::size_t version_{0};
};

} // namespace linoh::util
