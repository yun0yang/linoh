#pragma once

#include <atomic>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>

namespace linoh::util::log {

enum class Level : int { Trace = 0, Debug = 1, Info = 2, Warn = 3, Error = 4 };

inline std::atomic<int> &global_level() {
    static std::atomic<int> lvl{static_cast<int>(Level::Info)};
    return lvl;
}

inline void set_level(Level l) { global_level().store(static_cast<int>(l)); }

inline std::string_view level_name(Level l) {
    switch (l) {
        case Level::Trace: return "TRACE";
        case Level::Debug: return "DEBUG";
        case Level::Info: return "INFO ";
        case Level::Warn: return "WARN ";
        case Level::Error: return "ERROR";
    }
    return "?????";
}

inline std::string timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

/// 把所有参数串联输出到 `std::cout` 的辅助函数。
template <typename T>
void append_args(std::ostringstream &oss, T &&arg) {
    oss << " " << std::forward<T>(arg);
}

template <typename First, typename Second, typename... Rest>
void append_args(std::ostringstream &oss, First &&first, Second &&second, Rest &&... rest) {
    oss << " " << std::forward<First>(first);
    append_args(oss, std::forward<Second>(second), std::forward<Rest>(rest)...);
}

template <typename... Args>
void log(Level level, std::string_view fmt, Args &&... args) {
    if (static_cast<int>(level) < global_level().load()) return;

    static std::mutex log_mutex;
    std::lock_guard<std::mutex> lk(log_mutex);

    std::ostringstream oss;
    oss << "[" << timestamp() << "] [" << level_name(level) << "] " << fmt;
    if constexpr (sizeof...(Args) > 0) {
        append_args(oss, std::forward<Args>(args)...);
    }
    std::cerr << oss.str() << std::endl;
}

} // namespace linoh::util::log

// ============================================================================
// 编译期日志级别守卫 (P-LOG-1 性能优化)
// ============================================================================
// LINOH_COMPILE_LOG_LEVEL 通过预处理器在编译期剥离 <= 该级别的日志调用，
// 实现真正的零开销：被剥离的日志点不产生任何指令、不评估参数、不持锁。
//
// 默认 0 (Trace) 保留全部日志，仅靠运行时 set_level() 过滤（向后兼容）。
// 生产构建应定义 /DLINOH_COMPILE_LOG_LEVEL=2 (Info) 剥离 Debug/Trace ——
// 这对热路径（handle_incoming 每包 12+ 个 LINOH_DEBUG、BBR on_ack 每 ACK）
// 至关重要：消除函数调用 + 原子加载 + 参数压栈开销。
//
// 级别值与 Level 枚举一致：0=Trace 1=Debug 2=Info 3=Warn 4=Error
#ifndef LINOH_COMPILE_LOG_LEVEL
#define LINOH_COMPILE_LOG_LEVEL 0
#endif

#define LINOH_COMPILE_LVL_TRACE 0
#define LINOH_COMPILE_LVL_DEBUG 1
#define LINOH_COMPILE_LVL_INFO  2
#define LINOH_COMPILE_LVL_WARN  3
#define LINOH_COMPILE_LVL_ERROR 4

#if LINOH_COMPILE_LOG_LEVEL <= LINOH_COMPILE_LVL_TRACE
#  define LINOH_TRACE(...) ::linoh::util::log::log(::linoh::util::log::Level::Trace, __VA_ARGS__)
#else
#  define LINOH_TRACE(...) do {} while(0)
#endif

#if LINOH_COMPILE_LOG_LEVEL <= LINOH_COMPILE_LVL_DEBUG
#  define LINOH_DEBUG(...) ::linoh::util::log::log(::linoh::util::log::Level::Debug, __VA_ARGS__)
#else
#  define LINOH_DEBUG(...) do {} while(0)
#endif

#if LINOH_COMPILE_LOG_LEVEL <= LINOH_COMPILE_LVL_INFO
#  define LINOH_INFO(...)  ::linoh::util::log::log(::linoh::util::log::Level::Info,  __VA_ARGS__)
#else
#  define LINOH_INFO(...)  do {} while(0)
#endif

#if LINOH_COMPILE_LOG_LEVEL <= LINOH_COMPILE_LVL_WARN
#  define LINOH_WARN(...)  ::linoh::util::log::log(::linoh::util::log::Level::Warn,  __VA_ARGS__)
#else
#  define LINOH_WARN(...)  do {} while(0)
#endif

#if LINOH_COMPILE_LOG_LEVEL <= LINOH_COMPILE_LVL_ERROR
#  define LINOH_ERROR(...) ::linoh::util::log::log(::linoh::util::log::Level::Error, __VA_ARGS__)
#else
#  define LINOH_ERROR(...) do {} while(0)
#endif
