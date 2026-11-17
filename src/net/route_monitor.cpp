// linoh/net/route_monitor.cpp — Network route change monitoring implementation
//
// v1.7.0.1 P0: A4 网络变更后改进打洞 (借鉴 iroh #3928 + #4039)

#include "linoh/net/route_monitor.hpp"

#include <atomic>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#if defined(__linux__)
#include <filesystem>
#include <fstream>
#endif

#ifdef _WIN32
// Windows: NotifyRouteChange2 + IPForwardChanged2
// 必须在 windows.h 之前包含 winsock2.h（避免 winsock.h 冲突）
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#elif defined(__linux__)
// Linux: netlink RTM_NEWROUTE/RTM_DELROUTE
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>
#elif defined(__APPLE__)
// macOS: SCNetworkReachability（简化实现，仅探测默认路由变化）
#include <SystemConfiguration/SystemConfiguration.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

namespace linoh::net {

// ============================================================================
// RouteEvent 字符串化
// ============================================================================

const char *to_string(RouteEvent ev) noexcept {
    switch (ev) {
        case RouteEvent::DefaultRouteChanged: return "DefaultRouteChanged";
        case RouteEvent::InterfaceUp:         return "InterfaceUp";
        case RouteEvent::InterfaceDown:       return "InterfaceDown";
        case RouteEvent::AddressAdded:        return "AddressAdded";
        case RouteEvent::AddressRemoved:      return "AddressRemoved";
    }
    return "Unknown";
}

// ============================================================================
// RouteMonitor::Impl — 平台特定实现
// ============================================================================

struct RouteMonitor::Impl {
    RouteChangeCallback callback;
    std::mutex callback_mutex;
    std::atomic<bool> running{false};

#ifdef _WIN32
    // NotifyIpInterfaceChange 的通知句柄（callback-based，无需 OVERLAPPED/线程）
    HANDLE notify_handle{nullptr};
    // nn-L3 (v1.7.0.8): 删除从未使用的 stop_event/overlapped/watcher_thread。
    //   这三个成员原为 NotifyRouteChange2 + OVERLAPPED + 后台线程 设计，
    //   但实际 Windows 实现改用了 NotifyIpInterfaceChange（callback-based，
    //   由系统在线程池上下文调用 static_callback），不需要事件等待、不需要
    //   OVERLAPPED、也不需要 watcher_thread。stop_event 虽然被 Create/Set/
    //   Close 但从未被任何 Wait 函数等待，纯属无意义操作。

    // 静态回调（Windows 在 IOCP/线程池上下文调用）
    // 注意：Windows API 签名为 PINTERFACE_ROUTER_CHANGE_CALLBACK，
    // 参数是 CallerContext, Row, NotificationType
    static void WINAPI static_callback(PVOID context, PMIB_IPFORWARD_ROW2 row, MIB_NOTIFICATION_TYPE type) {
        auto *self = static_cast<Impl *>(context);
        if (!self || !self->running.load()) return;

        // 判断是否默认路由（dest 0.0.0.0/0）
        RouteEvent ev = RouteEvent::DefaultRouteChanged;
        if (row) {
            // 检查是否默认路由（dwForwardDest 为 0）
            // MIB_IPFORWARD_ROW2 的 DestinationPrefix.Prefix.si_addr
            // 简化：所有路由变更都触发 DefaultRouteChanged（用户侧可去重）
            ev = RouteEvent::DefaultRouteChanged;
        }

        RouteChangeCallback cb_copy;
        {
            std::lock_guard<std::mutex> lk(self->callback_mutex);
            cb_copy = self->callback;
        }
        if (cb_copy) cb_copy(ev);
    }
#elif defined(__linux__)
    int nl_sock{-1};
    std::thread nl_thread;
    std::atomic<bool> thread_running{false};

    void nl_loop() {
        char buf[4096];
        struct sockaddr_nl nladdr{};
        nladdr.nl_family = AF_NETLINK;

        while (thread_running.load()) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(nl_sock, &fds);

            struct timeval tv;
            tv.tv_sec = 1;   // 1s 超时，便于检查 thread_running
            tv.tv_usec = 0;

            int ret = ::select(nl_sock + 1, &fds, nullptr, nullptr, &tv);
            if (ret <= 0) continue;

            ssize_t len = ::recv(nl_sock, buf, sizeof(buf), 0);
            if (len <= 0) continue;

            // 解析 netlink 消息
            struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
            for (; NLMSG_OK(nlh, static_cast<size_t>(len)); nlh = NLMSG_NEXT(nlh, len)) {
                if (nlh->nlmsg_type == RTM_NEWROUTE || nlh->nlmsg_type == RTM_DELROUTE) {
                    RouteChangeCallback cb_copy;
                    {
                        std::lock_guard<std::mutex> lk(callback_mutex);
                        cb_copy = callback;
                    }
                    if (cb_copy) cb_copy(RouteEvent::DefaultRouteChanged);
                }
            }
        }
    }
#elif defined(__APPLE__)
    SCNetworkReachabilityRef reachability{nullptr};
    SCNetworkReachabilityContext ctx{};
    std::atomic<bool> thread_running{false};
    CFRunLoopRef cf_runloop{nullptr};
    std::thread cf_thread;

    static void reachability_callback(SCNetworkReachabilityRef target,
                                       SCNetworkReachabilityFlags flags,
                                       void *info) {
        auto *self = static_cast<Impl *>(info);
        if (!self || !self->running.load()) return;

        RouteChangeCallback cb_copy;
        {
            std::lock_guard<std::mutex> lk(self->callback_mutex);
            cb_copy = self->callback;
        }
        if (cb_copy) cb_copy(RouteEvent::DefaultRouteChanged);
    }

    /// macOS 后台线程：在独立 CFRunLoop 上调度 SCNetworkReachability，
    /// 否则 callback 永远不会被触发（必须在 RunLoop 上 schedule 才生效）。
    void cf_loop() {
        // 获取当前线程的 RunLoop
        cf_runloop = ::CFRunLoopGetCurrent();
        // 将 reachability schedule 到当前 RunLoop（kCFRunLoopDefaultMode）
        ::SCNetworkReachabilityScheduleWithRunLoop(
            reachability, cf_runloop, kCFRunLoopDefaultMode);
        thread_running.store(true);
        // 运行 RunLoop，直到 stop_internal 通过 CFRunLoopStop 退出
        ::CFRunLoopRun();
        // 退出后 unschedule
        ::SCNetworkReachabilityUnscheduleFromRunLoop(
            reachability, cf_runloop, kCFRunLoopDefaultMode);
        thread_running.store(false);
    }
#endif

    Impl() = default;

    ~Impl() {
        stop_internal();
    }

    bool start_internal(RouteChangeCallback cb) {
        if (running.load()) return true;  // 幂等

        {
            std::lock_guard<std::mutex> lk(callback_mutex);
            callback = std::move(cb);
        }

#ifdef _WIN32
        // nn-L3 (v1.7.0.8): 删除 stop_event 创建逻辑（从未被 Wait，纯死代码）。
        //   注册路由变更通知使用 NotifyIpInterfaceChange（callback-based）。
        // NotifyIpInterfaceChange 签名：Family, Callback, CallerContext, InitialNotification, NotificationHandle
        DWORD family = AF_INET;  // IPv4（可扩展为 AF_UNSPEC）
        DWORD win_ret = ::NotifyIpInterfaceChange(
            family,
            [](PVOID ctx, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE type) {
                auto *self = static_cast<Impl *>(ctx);
                if (!self || !self->running.load()) return;
                RouteEvent ev = RouteEvent::DefaultRouteChanged;
                RouteChangeCallback cb_copy;
                {
                    std::lock_guard<std::mutex> lk(self->callback_mutex);
                    cb_copy = self->callback;
                }
                if (cb_copy) cb_copy(ev);
            },
            this,
            FALSE,
            &notify_handle);

        if (win_ret != NO_ERROR) {
            return false;
        }

        running.store(true);
        return true;
#elif defined(__linux__)
        nl_sock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (nl_sock < 0) return false;

        struct sockaddr_nl addr{};
        addr.nl_family = AF_NETLINK;
        addr.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;

        if (::bind(nl_sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
            ::close(nl_sock);
            nl_sock = -1;
            return false;
        }

        running.store(true);
        thread_running.store(true);
        nl_thread = std::thread([this] { nl_loop(); });
        return true;
#elif defined(__APPLE__)
        reachability = ::SCNetworkReachabilityCreateWithName(nullptr, "0.0.0.0");
        if (!reachability) return false;

        ctx.info = this;
        ctx.retain = nullptr;
        ctx.release = nullptr;
        ctx.copyDescription = nullptr;

        if (!::SCNetworkReachabilitySetCallback(reachability, reachability_callback, &ctx)) {
            ::CFRelease(reachability);
            reachability = nullptr;
            return false;
        }

        // 必须在独立线程的 CFRunLoop 上 schedule，否则 callback 永不触发。
        running.store(true);
        cf_thread = std::thread([this] { cf_loop(); });
        // 等待 cf_loop 完成 schedule（确保 thread_running=true 后再返回）
        while (!thread_running.load() && running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return true;
#else
        // 不支持平台
        return false;
#endif
    }

    void stop_internal() {
        if (!running.exchange(false)) return;

#ifdef _WIN32
        if (notify_handle) {
            ::CancelMibChangeNotify2(notify_handle);
            notify_handle = nullptr;
        }
        // nn-L3 (v1.7.0.8): 删除 stop_event Set/Close（已从成员移除）
#elif defined(__linux__)
        thread_running.store(false);
        if (nl_sock >= 0) {
            ::close(nl_sock);
            nl_sock = -1;
        }
        if (nl_thread.joinable()) nl_thread.join();
#elif defined(__APPLE__)
        // 停止 CFRunLoop，cf_loop 会退出并 unschedule
        if (cf_runloop) {
            ::CFRunLoopStop(cf_runloop);
            cf_runloop = nullptr;
        }
        if (cf_thread.joinable()) cf_thread.join();
        if (reachability) {
            ::CFRelease(reachability);
            reachability = nullptr;
        }
#endif

        std::lock_guard<std::mutex> lk(callback_mutex);
        callback = nullptr;
    }
};

// ============================================================================
// RouteMonitor 公共 API
// ============================================================================

RouteMonitor::RouteMonitor() : impl_(std::make_unique<Impl>()) {}
RouteMonitor::~RouteMonitor() { stop(); }

bool RouteMonitor::start(RouteChangeCallback cb) {
    return impl_->start_internal(std::move(cb));
}

void RouteMonitor::stop() {
    impl_->stop_internal();
}

bool RouteMonitor::is_running() const noexcept {
    return impl_ && impl_->running.load();
}

bool RouteMonitor::platform_supported() noexcept {
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
    return true;
#else
    return false;
#endif
}

// ============================================================================
// DefaultRoutePoller 实现
// ============================================================================

DefaultRoutePoller::DefaultRoutePoller(
    std::chrono::milliseconds initial_interval,
    std::chrono::milliseconds max_interval)
    : initial_(initial_interval)
    , max_(max_interval)
    , current_ms_(static_cast<std::uint64_t>(initial_interval.count())) {}

DefaultRoutePoller::~DefaultRoutePoller() { stop(); }

void DefaultRoutePoller::start(RouteChangeCallback cb) {
    // v1.7.0.7 net H9: 用 start_stop_mu_ 串行化 start/stop，避免 TOCTOU
    //   原 start 用 mutex_ 保护检查-设置序列，但 stop 的 exchange 在 mutex_ 外，
    //   导致 start/stop 并发时 stop 的 cb_=nullptr 可能覆盖 start 新设置的 cb_。
    //   现在两者都先获取 start_stop_mu_，保证"检查 running_ -> 设置 running_ -> 启动/停止线程"原子。
    std::lock_guard<std::mutex> ss_lk(start_stop_mu_);
    std::lock_guard<std::mutex> lk(mutex_);
    if (running_.load()) {
        // 已运行：仅更新 callback
        cb_ = std::move(cb);
        return;
    }

    cb_ = std::move(cb);
    current_ms_.store(static_cast<std::uint64_t>(initial_.count()));
    last_route_signature_.clear();
    running_.store(true);
    thread_ = std::thread([this] { poll_loop(); });
}

void DefaultRoutePoller::stop() {
    // v1.7.0.7 net H9: 用 start_stop_mu_ 串行化，避免与并发 start() 竞争
    //   持 start_stop_mu_ 期间 exchange running_=false + join thread_，
    //   join 期间 poll_loop 仍在跑但不获取 start_stop_mu_（只获取 mutex_），不会死锁。
    //   join 完成后再锁 mutex_ 清空 cb_，保证不会被并发 start 覆盖。
    std::lock_guard<std::mutex> ss_lk(start_stop_mu_);
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
    std::lock_guard<std::mutex> lk(mutex_);
    cb_ = nullptr;
}

void DefaultRoutePoller::reset_interval() {
    current_ms_.store(static_cast<std::uint64_t>(initial_.count()));
}

std::chrono::milliseconds DefaultRoutePoller::current_interval() const {
    return std::chrono::milliseconds(static_cast<long long>(current_ms_.load()));
}

std::chrono::milliseconds DefaultRoutePoller::next_interval(
    std::chrono::milliseconds cur) const {
    auto next_ms = cur.count() * 2;
    auto max_ms = max_.count();
    if (next_ms > max_ms) next_ms = max_ms;
    return std::chrono::milliseconds(static_cast<long long>(next_ms));
}

bool DefaultRoutePoller::probe_once() {
    // 探测默认路由签名
    std::string sig;
#if defined(_WIN32)
    // Windows: 用 GetBestRoute 获取默认路由
    // 简化：用 GetIpForwardTable 查找 dest=0.0.0.0 的路由
    PMIB_IPFORWARDTABLE table = nullptr;
    DWORD size = 0;
    DWORD ret = ::GetIpForwardTable(nullptr, &size, FALSE);
    if (ret == ERROR_INSUFFICIENT_BUFFER) {
        table = reinterpret_cast<PMIB_IPFORWARDTABLE>(::malloc(size));
        if (!table) return false;
        ret = ::GetIpForwardTable(table, &size, FALSE);
    }
    if (ret != NO_ERROR || !table) {
        if (table) ::free(table);
        return false;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &row = table->table[i];
        if (row.dwForwardDest == 0) {
            // 默认路由
            std::ostringstream oss;
            oss << row.dwForwardNextHop << ":" << row.dwForwardIfIndex;
            sig = oss.str();
            break;
        }
    }
    ::free(table);
#elif defined(__linux__)
    // Linux: 读 /proc/net/route 查找 default route
    FILE *fp = ::fopen("/proc/net/route", "r");
    if (!fp) return false;

    char line[256];
    // 跳过表头
    if (!::fgets(line, sizeof(line), fp)) {
        ::fclose(fp);
        return false;
    }

    while (::fgets(line, sizeof(line), fp)) {
        char iface[64];
        unsigned long dest, gw;
        int flags;
        if (::sscanf(line, "%63s %lx %lx %x", iface, &dest, &gw, &flags) >= 3) {
            if (dest == 0) {  // 默认路由
                std::ostringstream oss;
                oss << gw << ":" << iface;
                sig = oss.str();
                break;
            }
        }
    }
    ::fclose(fp);
#else
    // 其他平台：无法探测，返回 false（无变化）
    return false;
#endif

    bool changed = false;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        if (!last_route_signature_.empty() && last_route_signature_ != sig) {
            changed = true;
        }
        last_route_signature_ = sig;
    }
    return changed;
}

void DefaultRoutePoller::poll_loop() {
    while (running_.load()) {
        auto cur = current_interval();
        // 睡眠 cur 毫秒（分片 100ms 检查 running_）
        auto remaining_ms = cur.count();
        while (remaining_ms > 0 && running_.load()) {
            auto step = (remaining_ms > 100) ? 100 : remaining_ms;
            std::this_thread::sleep_for(std::chrono::milliseconds(step));
            remaining_ms -= step;
        }
        if (!running_.load()) break;

        // 探测默认路由
        if (probe_once()) {
            // 路由变更，触发回调
            RouteChangeCallback cb_copy;
            {
                std::lock_guard<std::mutex> lk(mutex_);
                cb_copy = cb_;
            }
            if (cb_copy) cb_copy(RouteEvent::DefaultRouteChanged);

            // 重置到初始间隔（重新进入快速探测）
            reset_interval();
        } else {
            // 无变化，指数退避
            auto cur_after = current_interval();
            auto next = next_interval(cur_after);
            current_ms_.store(static_cast<std::uint64_t>(next.count()));
        }
    }
}

// ============================================================================
// P2-G7 网络类型感知实现
// ============================================================================

NetworkType detect_network_type() noexcept {
#ifdef _WIN32
    // Windows: GetAdaptersAddresses + IfType
    // IF_TYPE_ETHERNET_CSMACD = 6, IF_TYPE_IEEE80211 = 71, IF_TYPE_SOFTWARE_LOOPBACK = 24
    ULONG buf_len = 0;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // 第一次调用获取所需缓冲区大小
    if (GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &buf_len)
        == ERROR_BUFFER_OVERFLOW) {
        std::vector<std::uint8_t> buf(buf_len);
        PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        DWORD ret = GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &buf_len);
        if (ret == NO_ERROR) {
            NetworkType found = NetworkType::Unknown;
            for (PIP_ADAPTER_ADDRESSES a = adapters; a; a = a->Next) {
                // 跳过未启用的接口
                if (a->OperStatus != IfOperStatusUp) continue;
                // 跳过回环
                if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
                    found = NetworkType::Loopback;
                    continue;
                }
                if (a->IfType == IF_TYPE_IEEE80211) {
                    return NetworkType::WiFi;  // WiFi 优先级高
                }
                if (a->IfType == IF_TYPE_ETHERNET_CSMACD) {
                    found = NetworkType::Ethernet;
                }
            }
            return found;
        }
    }
    return NetworkType::Unknown;
#elif defined(__linux__)
    // Linux: /sys/class/net/*/type（802.11=WiFi, 1=Ethernet）+ operstate
    try {
        NetworkType found = NetworkType::Unknown;
        for (const auto &entry : std::filesystem::directory_iterator("/sys/class/net")) {
            std::string ifname = entry.path().filename().string();
            if (ifname == "lo") {
                found = NetworkType::Loopback;
                continue;
            }
            // 读 operstate
            std::ifstream operstate(entry.path() / "operstate");
            std::string state;
            if (operstate >> state && state != "up") continue;
            // 读 type
            std::ifstream type_file(entry.path() / "type");
            int type_val = 0;
            if (!(type_file >> type_val)) continue;
            // type 802.11 = 801 (ARPHRD_IEEE80211), 但实际 /sys/class/net/type 对 wifi
            // 常见值：1=Ethernet, 801=IEEE802.11, 772=Loopback
            // 判断 wifi：接口名以 wlan/wlp 开头 或 type==801
            if (type_val == 801 || ifname.rfind("wlan", 0) == 0 ||
                ifname.rfind("wlp", 0) == 0) {
                return NetworkType::WiFi;
            }
            if (type_val == 1) {
                found = NetworkType::Ethernet;
            }
        }
        return found;
    } catch (...) {
        return NetworkType::Unknown;
    }
#elif defined(__APPLE__)
    // macOS: SCNetworkReachability flags（kSCNetworkReachabilityFlagsIsWWAN=Cellular）
    SCNetworkReachabilityRef ref = SCNetworkReachabilityCreateWithName(nullptr, "0.0.0.0");
    if (!ref) return NetworkType::Unknown;
    SCNetworkReachabilityFlags flags = 0;
    bool ok = SCNetworkReachabilityGetFlags(ref, &flags);
    CFRelease(ref);
    if (!ok) return NetworkType::Unknown;
    if (flags & kSCNetworkReachabilityFlagsIsWWAN) return NetworkType::Cellular;
    if (flags & kSCNetworkReachabilityFlagsReachable) return NetworkType::WiFi;
    return NetworkType::Unknown;
#else
    return NetworkType::Unknown;
#endif
}

std::string NetworkChangeEvent::to_string() const {
    std::ostringstream oss;
    oss << "{from=" << linoh::net::to_string(from)
        << ", to=" << linoh::net::to_string(to)
        << ", trigger=" << linoh::net::to_string(trigger)
        << ", actual_change=" << (is_actual_change() ? "true" : "false")
        << "}";
    return oss.str();
}

// ============================================================================
// P2-G7 NetworkChangeTracker 实现
// ============================================================================

NetworkChangeTracker::NetworkChangeTracker(Config config)
    : config_(config),
      type_provider_([]() { return detect_network_type(); }) {
    if (config_.enable_route_monitor) {
        route_monitor_ = std::make_unique<RouteMonitor>();
    }
}

NetworkChangeTracker::NetworkChangeTracker(Config config, NetworkTypeProvider type_provider)
    : config_(config),
      type_provider_(std::move(type_provider)) {
    // 测试模式：enable_route_monitor=false 时不创建 RouteMonitor
    if (config_.enable_route_monitor) {
        route_monitor_ = std::make_unique<RouteMonitor>();
    }
}

NetworkChangeTracker::~NetworkChangeTracker() {
    stop();
}

bool NetworkChangeTracker::start(NetworkChangeCallback cb) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (running_.load()) return true;  // 已运行

    callback_ = std::move(cb);
    current_type_ = type_provider_ ? type_provider_() : NetworkType::Unknown;
    last_triggered_type_ = current_type_;  // 初始化为当前类型，避免启动即触发
    running_.store(true);
    debounce_stop_.store(false);

    // 启动去抖动线程
    debounce_thread_ = std::thread([this]() { this->debounce_loop(); });

    // 启动 RouteMonitor
    bool route_started = false;
    if (route_monitor_) {
        route_started = route_monitor_->start([this](RouteEvent ev) {
            this->handle_route_event(ev);
        });
    }
    if (!route_started && config_.fallback_to_poller) {
        route_poller_ = std::make_unique<DefaultRoutePoller>();
        route_poller_->start([this](RouteEvent ev) {
            this->handle_route_event(ev);
        });
    }
    return true;
}

void NetworkChangeTracker::stop() {
    if (!running_.exchange(false)) return;
    debounce_stop_.store(true);
    if (debounce_thread_.joinable()) debounce_thread_.join();
    if (route_monitor_) route_monitor_->stop();
    if (route_poller_) route_poller_->stop();
    std::lock_guard<std::mutex> lk(mutex_);
    callback_ = nullptr;
}

bool NetworkChangeTracker::is_running() const noexcept {
    return running_.load();
}

NetworkType NetworkChangeTracker::current_type() const noexcept {
    return current_type_;
}

void NetworkChangeTracker::inject_event(RouteEvent ev) {
    handle_route_event(ev);
}

std::optional<NetworkChangeEvent> NetworkChangeTracker::debounce_event(
    NetworkType last_triggered_type,
    NetworkType new_type,
    RouteEvent trigger) {
    if (new_type == last_triggered_type) {
        return std::nullopt;  // 同类型，不触发
    }
    NetworkChangeEvent ev;
    ev.from = last_triggered_type;
    ev.to = new_type;
    ev.trigger = trigger;
    ev.timestamp = std::chrono::steady_clock::now();
    return ev;
}

void NetworkChangeTracker::handle_route_event(RouteEvent ev) {
    std::lock_guard<std::mutex> lk(mutex_);
    // 记录待处理事件（覆盖之前的，取最后一个）
    pending_event_ = ev;
    pending_event_time_ = std::chrono::steady_clock::now();
}

void NetworkChangeTracker::debounce_loop() {
    while (!debounce_stop_.load()) {
        // 短睡眠轮询（50ms 粒度，配合 300ms debounce_window）
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (debounce_stop_.load()) break;

        std::optional<RouteEvent> event_to_process;
        std::chrono::steady_clock::time_point event_time;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (pending_event_.has_value()) {
                auto elapsed = std::chrono::steady_clock::now() - pending_event_time_;
                if (elapsed >= config_.debounce_window) {
                    // 去抖动窗口已过，处理事件
                    event_to_process = pending_event_;
                    event_time = pending_event_time_;
                    pending_event_.reset();
                }
            }
        }

        if (event_to_process.has_value()) {
            // 探测当前网络类型
            NetworkType new_type = type_provider_ ? type_provider_() : NetworkType::Unknown;
            NetworkType last_type;
            NetworkChangeCallback cb_copy;
            {
                std::lock_guard<std::mutex> lk(mutex_);
                current_type_ = new_type;
                last_type = last_triggered_type_;
                cb_copy = callback_;
            }
            // 调用去抖动纯逻辑
            auto change = debounce_event(last_type, new_type, *event_to_process);
            if (change.has_value() && cb_copy) {
                {
                    std::lock_guard<std::mutex> lk(mutex_);
                    last_triggered_type_ = new_type;
                }
                cb_copy(*change);
            }
        }
    }
}

}  // namespace linoh::net
