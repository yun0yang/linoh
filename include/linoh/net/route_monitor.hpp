// linoh/net/route_monitor.hpp — Network route change monitoring
//
// v1.7.0.1 P0: A4 网络变更后改进打洞 (借鉴 iroh #3928 + #4039)
//
//   - RouteMonitor: 系统路由表变更事件监测（异步回调）
//       Windows : NotifyRouteChange2 + IPForwardChanged2
//       Linux   : netlink RTM_NEWROUTE/RTM_DELROUTE socket
//       macOS   : SCNetworkReachability + system configuration notification
//       其他    : start() 返回 false，由上层降级到 DefaultRoutePoller
//
//   - DefaultRoutePoller: 默认路由轮询兜底（指数退避 200ms -> 5s 上限）
//
// 线程模型：
//   - RouteMonitor 平台回调在系统线程触发，内部 mutex 保护 callback，
//     转发到用户 callback 时不持有锁，避免死锁。
//   - DefaultRoutePoller 内部独立线程轮询，回调在该线程触发。

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace linoh::net {

/// 网络变更事件类型
enum class RouteEvent {
    DefaultRouteChanged,    // 默认网关变更（最关键，触发重打洞）
    InterfaceUp,            // 网卡启用
    InterfaceDown,          // 网卡禁用
    AddressAdded,           // 新 IP 地址
    AddressRemoved,         // IP 地址移除
};

/// 路由变更回调（异步线程调用，用户需保证线程安全）
using RouteChangeCallback = std::function<void(RouteEvent)>;

// ============================================================================
// P2-G7 网络类型感知（网络切换重建）
// ============================================================================
//
// 借鉴 tdesktop 网络类型检测（WiFi/Cellular 切换触发重建）+ iroh 网络变更重建：
// 在 RouteEvent 基础上增加 NetworkType 感知，仅在网络类型实际变化时触发重建，
// 避免同类型路由变更（如 WiFi 信道切换）导致不必要的连接重建。
//
// 检测策略：
//   - Windows: GetAdaptersAddresses + IfType（IF_TYPE_IEEE80211=WiFi, IF_TYPE_ETHERNET_CSMACD=Ethernet）
//   - Linux: /sys/class/net/*/type（802.11=WiFi, 1=Ethernet）+ operstate
//   - macOS: SCNetworkReachability flags（kSCNetworkReachabilityFlagsIsWWAN=Cellular）
//   - 不支持平台返回 Unknown（不阻塞重建，由上层决定是否降级）

/// 网络类型枚举
enum class NetworkType : std::uint8_t {
    Unknown  = 0,  // 未知/不支持检测
    WiFi     = 1,  // 无线局域网
    Cellular = 2,  // 蜂窝移动网络（4G/5G）
    Ethernet = 3,  // 有线以太网
    Loopback = 4,  // 本地回环（仅测试环境）
};

/// NetworkType 转字符串（用于日志/测试）
inline const char *to_string(NetworkType t) noexcept {
    switch (t) {
        case NetworkType::Unknown:  return "unknown";
        case NetworkType::WiFi:     return "wifi";
        case NetworkType::Cellular: return "cellular";
        case NetworkType::Ethernet: return "ethernet";
        case NetworkType::Loopback: return "loopback";
    }
    return "unknown";
}

/// 网络类型变化事件（G7 重建触发依据）
struct NetworkChangeEvent {
    NetworkType from{NetworkType::Unknown};  ///< 变化前网络类型
    NetworkType to{NetworkType::Unknown};    ///< 变化后网络类型
    RouteEvent trigger{RouteEvent::DefaultRouteChanged};  ///< 触发的路由事件
    std::chrono::steady_clock::time_point timestamp{std::chrono::steady_clock::now()};

    /// 是否为实际类型变化（from != to）
    bool is_actual_change() const noexcept { return from != to; }

    /// 转字符串（用于日志）
    std::string to_string() const;
};

/// 网络类型变化回调（去抖动后触发，仅在实际类型变化时调用）
using NetworkChangeCallback = std::function<void(const NetworkChangeEvent &)>;

/// 探测当前网络类型（平台特定实现）
///
/// Windows: GetAdaptersAddresses + IfType
/// Linux: /sys/class/net/*/type + operstate
/// macOS: SCNetworkReachability flags
/// 不支持平台返回 NetworkType::Unknown
NetworkType detect_network_type() noexcept;

/// 路由变更监测器（借鉴 iroh #3928）
///
/// 平台实现：
///   - Windows: NotifyRouteChange2 + IPForwardChanged2 回调
///   - Linux: netlink RTM_NEWROUTE/RTM_DELROUTE socket
///   - macOS: SCNetworkReachability + system configuration notification
///
/// 线程模型：平台回调在系统线程触发，RouteMonitor 内部 mutex 保护 callback，
/// 转发到用户 callback 时无锁持有，避免死锁。
class RouteMonitor {
public:
    RouteMonitor();
    ~RouteMonitor();

    RouteMonitor(const RouteMonitor &) = delete;
    RouteMonitor &operator=(const RouteMonitor &) = delete;
    RouteMonitor(RouteMonitor &&) = delete;
    RouteMonitor &operator=(RouteMonitor &&) = delete;

    /// 启动监测（返回 false 表示平台不支持或启动失败）
    bool start(RouteChangeCallback cb);

    /// 停止监测
    void stop();

    /// 是否正在监测
    bool is_running() const noexcept;

    /// 平台是否支持（编译期判定，非运行时探测）
    /// 用于上层决定是否直接降级到 DefaultRoutePoller
    static bool platform_supported() noexcept;

private:
    // 平台特定实现细节（pimpl 风格，避免把 winsock2.h / linux netlink.h 暴露到头文件）
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// 默认路由轮询器（借鉴 iroh #4039 指数退避）
///
/// 当 RouteMonitor 不可用（老系统/受限环境）时的兜底方案：
/// 定期探测默认路由是否变化，间隔按指数退避增加。
///
/// 退避序列（默认参数）：
///   100ms -> 200ms -> 400ms -> 800ms -> 1600ms -> 3200ms -> 5000ms（上限）
///
/// 路由变更确认后调用 reset_interval() 重新进入快速探测阶段。
class DefaultRoutePoller {
public:
    /// @param initial_interval 初始间隔（默认 100ms）
    /// @param max_interval 最大间隔（默认 5s）
    DefaultRoutePoller(
        std::chrono::milliseconds initial_interval = std::chrono::milliseconds(100),
        std::chrono::milliseconds max_interval = std::chrono::seconds(5));

    ~DefaultRoutePoller();

    DefaultRoutePoller(const DefaultRoutePoller &) = delete;
    DefaultRoutePoller &operator=(const DefaultRoutePoller &) = delete;
    DefaultRoutePoller(DefaultRoutePoller &&) = delete;
    DefaultRoutePoller &operator=(DefaultRoutePoller &&) = delete;

    /// 启动轮询（异步线程）。重复调用是幂等的：已运行时仅更新 callback。
    void start(RouteChangeCallback cb);

    /// 停止轮询
    void stop();

    /// 重置间隔到初始值（路由变更确认后调用，重新进入快速探测）
    void reset_interval();

    /// 当前间隔（用于测试）。若已停止则返回上一次使用的间隔。
    std::chrono::milliseconds current_interval() const;

    /// 是否正在运行
    bool is_running() const noexcept { return running_.load(); }

    /// 计算下一个间隔（current *= 2，上限 max_）。公开用于测试。
    std::chrono::milliseconds next_interval(std::chrono::milliseconds cur) const;

    /// 探测默认路由是否变化。公开用于测试（单次同步探测）。
    /// @return true 表示默认路由相对上次探测发生变化
    bool probe_once();

private:
    void poll_loop();

    std::chrono::milliseconds initial_;
    std::chrono::milliseconds max_;
    std::atomic<std::uint64_t> current_ms_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    mutable std::mutex mutex_;
    RouteChangeCallback cb_;
    // v1.7.0.7 net H9: 串行化 start/stop 操作，避免 TOCTOU
    //   根因：原 stop() 的 running_.exchange(false) 在 mutex_ 锁外，与并发 start() 竞争：
    //         stop 在 join 后用 cb_=nullptr 覆盖 start 新设置的 callback，回调丢失。
    //   修复：start_stop_mu_ 保证 start/stop 的"检查-设置-启动/停止"序列原子。
    //         poll_loop 只获取 mutex_（保护 cb_/last_route_signature_），不获取 start_stop_mu_，避免死锁。
    std::mutex start_stop_mu_;

    // 上一次探测到的默认路由签名（用于变化检测）
    // 签名定义：IPv4 默认网关字符串 + 接口索引（平台特定）
    std::string last_route_signature_;
};

/// 将 RouteEvent 转换为可读字符串（用于日志/测试）
const char *to_string(RouteEvent ev) noexcept;

// ============================================================================
// P2-G7 NetworkChangeTracker — 网络类型变化去抖动追踪器
// ============================================================================
//
// 借鉴 tdesktop ConnectionStatus 去抖动 + iroh 网络变更重建：
// 包装 RouteMonitor（或 DefaultRoutePoller 兜底），将 RouteEvent 映射为
// NetworkChangeEvent，去抖动后仅在 NetworkType 实际变化时触发回调。
//
// 去抖动策略：
//   - debounce_window（默认 300ms）内的连续事件合并为最后一个
//   - 定时器到期后检测 NetworkType 是否变化，变化才触发回调
//   - 同类型路由变更（WiFi→WiFi）不触发回调
//
// 可测试性：
//   - NetworkTypeProvider 可注入（测试时返回预设类型，不依赖平台）
//   - debounce_event() 纯逻辑方法可独立单元测试
//   - inject_event() 用于测试手动注入事件

/// 网络类型探测回调（可注入，测试用）
using NetworkTypeProvider = std::function<NetworkType()>;

/// 网络类型变化去抖动追踪器
class NetworkChangeTracker {
public:
    /// 配置
    struct Config {
        /// 去抖动窗口（默认 300ms，窗口内连续事件合并为最后一个）
        std::chrono::milliseconds debounce_window{std::chrono::milliseconds(300)};
        /// 是否启用 RouteMonitor（false 时仅靠 inject_event 手动驱动，测试用）
        bool enable_route_monitor{true};
        /// RouteMonitor 不可用时降级到 DefaultRoutePoller
        bool fallback_to_poller{true};
    };

    /// 默认构造（使用真实 RouteMonitor + detect_network_type）
    explicit NetworkChangeTracker();
    /// 带 Config 构造
    explicit NetworkChangeTracker(Config config);

    /// 注入式构造（测试用：注入 type_provider 替代 detect_network_type）
    /// enable_route_monitor=false 时不启动 RouteMonitor，仅靠 inject_event 驱动
    NetworkChangeTracker(Config config, NetworkTypeProvider type_provider);

    ~NetworkChangeTracker();

    NetworkChangeTracker(const NetworkChangeTracker &) = delete;
    NetworkChangeTracker &operator=(const NetworkChangeTracker &) = delete;
    NetworkChangeTracker(NetworkChangeTracker &&) = delete;
    NetworkChangeTracker &operator=(NetworkChangeTracker &&) = delete;

    /// 启动追踪（返回 false 表示 RouteMonitor 启动失败且无 fallback）
    bool start(NetworkChangeCallback cb);

    /// 停止追踪
    void stop();

    /// 是否正在追踪
    bool is_running() const noexcept;

    /// 当前网络类型（最近一次探测结果）
    NetworkType current_type() const noexcept;

    /// 手动注入路由事件（测试用，模拟 RouteMonitor 回调）
    /// 内部走去抖动逻辑，可能在 debounce_window 后触发 cb
    void inject_event(RouteEvent ev);

    /// 去抖动纯逻辑（公开用于单元测试）
    ///
    /// 判断给定事件序列中，最后一个事件是否应触发类型变化回调。
    /// 规则：
    ///   - 探测当前类型 new_type
    ///   - new_type == last_triggered_type → 不触发（同类型）
    ///   - new_type != last_triggered_type → 触发，更新 last_triggered_type
    ///
    /// @param last_triggered_type 上次触发回调时的网络类型
    /// @param new_type 本次探测到的网络类型
    /// @return nullopt 表示不触发；有值表示触发的 NetworkChangeEvent
    static std::optional<NetworkChangeEvent> debounce_event(
        NetworkType last_triggered_type,
        NetworkType new_type,
        RouteEvent trigger);

private:
    void handle_route_event(RouteEvent ev);
    void debounce_loop();

    Config config_;
    NetworkTypeProvider type_provider_;
    std::unique_ptr<RouteMonitor> route_monitor_;
    std::unique_ptr<DefaultRoutePoller> route_poller_;

    mutable std::mutex mutex_;
    NetworkChangeCallback callback_;
    NetworkType current_type_{NetworkType::Unknown};
    NetworkType last_triggered_type_{NetworkType::Unknown};
    std::atomic<bool> running_{false};

    // 去抖动状态
    std::optional<RouteEvent> pending_event_;
    std::chrono::steady_clock::time_point pending_event_time_;
    std::thread debounce_thread_;
    std::atomic<bool> debounce_stop_{false};
};

}  // namespace linoh::net
