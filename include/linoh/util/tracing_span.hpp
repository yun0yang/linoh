// linoh/util/tracing_span.hpp — B8 连接级 tracing 事件（v1.7.0.4 P3）
//
// 借鉴 iroh v1.0+ 的 tracing span 层级设计：
// - endpoint 顶层 span（携带 node_id）
// - actor 子 span（继承父 span，携带 remote endpoint_id）
// - conn_id 作为日志字段约定
//
// C++ 实现：RAII guard + LINOH_CONN_LOG 宏（对标 Rust tracing::span + #[instrument]）
// 注：不使用 thread_local Span::current()（Rust task-local 模式），改用显式传参。

#pragma once

#include "linoh/util/logging.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace linoh::util {

// ============================================================================
// TracingSpan — 轻量级 RAII span guard
//
// 构造时记录 span 开始 + 字段，析构时记录 span 结束。
// 仅在 LINOH_TRACE 级别启用时输出，RELEASE 级别为空操作。
//
// 使用方式：
//   {
//       util::TracingSpan span("endpoint", {{"id", "7dn2ff6eptj2t"}});
//       // ... 业务逻辑 ...
//       LINOH_INFO("endpoint bound");
//   }  // span 析构，记录结束
// ============================================================================
class TracingSpan {
public:
    using Fields = std::vector<std::pair<std::string, std::string>>;

    TracingSpan(std::string name, Fields fields = {})
        : name_(std::move(name)),
          fields_(std::move(fields)),
          start_(std::chrono::steady_clock::now()) {
        // 记录 span 开始（DEBUG 级别）
        std::string fields_str = format_fields();
        LINOH_DEBUG("[span:start]", name_, fields_str);
    }

    ~TracingSpan() {
        auto end = std::chrono::steady_clock::now();
        auto dur_us = std::chrono::duration_cast<std::chrono::microseconds>(
                          end - start_).count();
        std::string fields_str = format_fields();
        LINOH_DEBUG("[span:end]", name_, fields_str, "duration_us=", dur_us);
    }

    // 禁止拷贝（避免 span 生命周期混乱）
    TracingSpan(const TracingSpan &) = delete;
    TracingSpan &operator=(const TracingSpan &) = delete;
    // 允许移动（用于 vector 存储）
    TracingSpan(TracingSpan &&) = default;
    TracingSpan &operator=(TracingSpan &&) = default;

    const std::string &name() const { return name_; }
    const Fields &fields() const { return fields_; }

private:
    std::string format_fields() const {
        if (fields_.empty()) return "";
        std::string s;
        for (const auto &[k, v] : fields_) {
            s += " ";
            s += k;
            s += "=";
            s += v;
        }
        return s;
    }

    std::string name_;
    Fields fields_;
    std::chrono::steady_clock::time_point start_;
};

// ============================================================================
// LINOH_CONN_LOG — 连接级日志宏（强制携带 conn_id）
//
// 对标 iroh: conn_id = conn.stable_id() 的 tracing field 约定
// 适配 linoh 日志风格：参数以空格串联输出（非 {} 占位符）
// 使用方式：
//   LINOH_CONN_LOG(conn, INFO, "connected remote_id=", remote, "alpn=", alpn);
// ============================================================================
#define LINOH_CONN_LOG(conn, level, ...) \
    do { \
        std::uint64_t _cid = (conn).stable_id(); \
        LINOH_##level("conn_id=", _cid, __VA_ARGS__); \
    } while (0)

// ============================================================================
// LINOH_EVENT — 带 target 前缀的结构化事件宏
//
// 对标 iroh: target: "iroh::_events::conn::connected" 的命名约定
// 使用方式：
//   LINOH_EVENT("linoh::_events::conn::connected", INFO,
//               "conn_id=", cid, "remote_id=", remote);
// ============================================================================
#define LINOH_EVENT(target, level, ...) \
    do { \
        LINOH_##level("[" target "]", __VA_ARGS__); \
    } while (0)

}  // namespace linoh::util
