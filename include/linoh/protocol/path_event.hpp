// linoh/protocol/path_event.hpp — B7/B8 路径事件枚举（v1.7.0.4 P3）
//
// 借鉴 iroh v1.0+ 的 PathEvent 设计：
// - 路径生命周期事件（Opened/Closed/Selected）
// - kClosed 携带 last_stats（PathStats 快照）
// - 通过 callback 分发给订阅方（如 ConnectionStatsAggregator）
//
// 对标 iroh: path_watcher.rs 的 PathEvent 枚举
// v4.7.0: 引入 PathEventStream（per-stream 有界队列）后，Lagged 事件适用 ——
//         单个 stream 消费者过慢导致队列溢出时触发，不影响其他订阅者。

#pragma once

#include "linoh/protocol/path_stats.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>

namespace linoh::protocol {

// ============================================================================
// PathEvent — 路径生命周期事件
// ============================================================================
struct PathEvent {
    enum class Type {
        kOpened,    // 路径加入 PathList
        kClosed,    // 路径放弃/关闭，携带 last_stats
        kSelected,  // 路径切换（新路径被选中）
        kLagged,    // v4.7.0: PathEventStream 队列溢出（消费者过慢），携带 lagged_count
    };

    Type type{Type::kOpened};
    std::uint64_t path_id{0};           // 路径标识
    std::string remote_addr;            // 对端传输地址（fmt）
    std::string local_addr;             // 本地传输地址（fmt）
    std::optional<PathStats> last_stats;  // 仅 kClosed 时填充
    std::string reason;                 // kClosed 的原因 / kSelected 的切换说明
    std::uint64_t lagged_count{0};      // v4.7.0: 仅 kLagged 时填充（累计溢出事件数）

    // 工厂方法
    static PathEvent opened(std::uint64_t path_id, std::string remote,
                            std::string local) {
        PathEvent ev;
        ev.type = Type::kOpened;
        ev.path_id = path_id;
        ev.remote_addr = std::move(remote);
        ev.local_addr = std::move(local);
        return ev;
    }

    static PathEvent closed(std::uint64_t path_id, std::string remote,
                            std::string local, PathStats stats,
                            std::string reason = "") {
        PathEvent ev;
        ev.type = Type::kClosed;
        ev.path_id = path_id;
        ev.remote_addr = std::move(remote);
        ev.local_addr = std::move(local);
        ev.last_stats = std::move(stats);
        ev.reason = std::move(reason);
        return ev;
    }

    static PathEvent selected(std::uint64_t path_id, std::string remote,
                              std::string local, std::string reason = "") {
        PathEvent ev;
        ev.type = Type::kSelected;
        ev.path_id = path_id;
        ev.remote_addr = std::move(remote);
        ev.local_addr = std::move(local);
        ev.reason = std::move(reason);
        return ev;
    }

    // v4.7.0: PathEventStream 队列溢出事件
    static PathEvent lagged(std::uint64_t path_id, std::uint64_t lagged_count) {
        PathEvent ev;
        ev.type = Type::kLagged;
        ev.path_id = path_id;
        ev.lagged_count = lagged_count;
        return ev;
    }

    // 类型判断便捷方法
    bool is_opened() const { return type == Type::kOpened; }
    bool is_closed() const { return type == Type::kClosed; }
    bool is_selected() const { return type == Type::kSelected; }
    bool is_lagged() const { return type == Type::kLagged; }
    bool has_last_stats() const { return last_stats.has_value(); }

    // 类型转字符串（用于日志/测试）
    static const char *type_str(Type t) {
        switch (t) {
            case Type::kOpened:   return "Opened";
            case Type::kClosed:   return "Closed";
            case Type::kSelected: return "Selected";
            case Type::kLagged:   return "Lagged";
            default:              return "Unknown";
        }
    }
};

// ============================================================================
// PathEventCallback — 事件分发回调
//
// PathMigrator 等路径管理器通过此回调将事件分发给订阅方。
// 回调内部异常不应影响路径迁移主流程，调用方应在 try/catch 中执行。
// ============================================================================
using PathEventCallback = std::function<void(const PathEvent &)>;

}  // namespace linoh::protocol
