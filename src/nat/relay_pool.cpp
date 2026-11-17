// relay_pool.cpp — P5-D-5 Relay 自动 fallback 实现
//
// 实现 RelayPool、CircuitBreaker、FailoverController

#include "linoh/nat/relay_pool.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <random>
#include <sstream>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace linoh::nat {

// ============================================================================
// CircuitBreaker 实现
// ============================================================================

CircuitBreaker::CircuitBreaker(CircuitBreakerConfig cfg)
    : config_(std::move(cfg)) {}

// nn-M6 (v1.7.0.8): 所有公共方法加 mutex_ 保护。原实现 state_/opened_at_/
// half_open_probes_/consecutive_* 等成员非 atomic 无锁，并发调用
// allow_request + record_success/record_failure 会出现：
//   - state_ 与 opened_at_ 不一致（看到 Open 但 opened_at_ 未设置）
//   - half_open_probes_ 计数丢失/超出上限
//   - consecutive_failures_ 与 state_ 状态机错乱
// 加锁后状态机原子可观察。
bool CircuitBreaker::allow_request() {
    std::lock_guard<std::mutex> lk(mutex_);
    switch (state_) {
        case CircuitState::Closed:
            return true;
        case CircuitState::Open:
            maybe_transition_to_half_open_locked();
            if (state_ == CircuitState::HalfOpen) {
                half_open_probes_++;
                return true;
            }
            return false;
        case CircuitState::HalfOpen:
            if (half_open_probes_ < config_.half_open_max_probes) {
                half_open_probes_++;
                return true;
            }
            return false;
    }
    return false;
}

void CircuitBreaker::record_success() {
    std::lock_guard<std::mutex> lk(mutex_);
    consecutive_failures_ = 0;
    consecutive_successes_++;
    total_checks_++;  // 仅在成功时计入 total，避免失败也计入

    if (state_ == CircuitState::HalfOpen) {
        if (consecutive_successes_ >= config_.close_threshold) {
            state_ = CircuitState::Closed;
            half_open_probes_ = 0;
            // v3.3.0 突破4: 成功恢复，重置连续熔断计数器
            consecutive_opens_ = 0;
        }
    }
}

void CircuitBreaker::record_failure() {
    std::lock_guard<std::mutex> lk(mutex_);
    consecutive_successes_ = 0;
    consecutive_failures_++;
    total_failures_++;

    if (state_ == CircuitState::HalfOpen) {
        // 半开状态探测失败 → 重新熔断
        // v3.3.0 突破4: consecutive_opens_ 递增（探测失败也算连续熔断，
        //   用于指数退避：每次探测失败 cooldown 翻倍，给 Relay 更多恢复时间）
        ++consecutive_opens_;
        state_ = CircuitState::Open;
        opened_at_ = std::chrono::system_clock::now();
        half_open_probes_ = 0;
    } else if (state_ == CircuitState::Closed) {
        if (consecutive_failures_ >= config_.failure_threshold) {
            // v3.3.0 突破4: 新触发熔断，连续熔断计数器 +1（用于指数退避）
            ++consecutive_opens_;
            state_ = CircuitState::Open;
            opened_at_ = std::chrono::system_clock::now();
        }
    }
}

// nn-M6 (v1.7.0.8): 锁内实现，调用方必须已持有 mutex_。
void CircuitBreaker::maybe_transition_to_half_open_locked() {
    if (state_ != CircuitState::Open) return;
    auto elapsed = std::chrono::system_clock::now() - opened_at_;
    // v3.3.0 突破4: 使用 effective_cooldown_locked() 替代固定 config_.cooldown
    //   连续熔断时 cooldown 指数退避，避免频繁打洞探测
    if (elapsed >= effective_cooldown_locked()) {
        state_ = CircuitState::HalfOpen;
        half_open_probes_ = 0;
        consecutive_successes_ = 0;
    }
}

// v3.3.0 突破4: 计算实际 cooldown（含指数退避）
std::chrono::milliseconds CircuitBreaker::effective_cooldown_locked() const {
    // consecutive_opens_=0（未熔断过）或 1（首次熔断）时，cooldown = config_.cooldown
    // consecutive_opens_=N（N>=2）时，cooldown = config_.cooldown * backoff_factor^(N-1)
    if (consecutive_opens_ <= 1) {
        return config_.cooldown;
    }
    double factor = 1.0;
    for (std::uint32_t i = 1; i < consecutive_opens_; ++i) {
        factor *= config_.backoff_factor;
    }
    double cooldown_ms = static_cast<double>(config_.cooldown.count()) * factor;
    double max_ms = static_cast<double>(config_.max_cooldown.count());
    if (cooldown_ms > max_ms) cooldown_ms = max_ms;
    return std::chrono::milliseconds(static_cast<std::int64_t>(cooldown_ms));
}

// nn-M6 (v1.7.0.8): 所有 getter 加锁返回快照，避免读到中间状态。
CircuitState CircuitBreaker::state() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return state_;
}

std::uint32_t CircuitBreaker::consecutive_failures() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return consecutive_failures_;
}

std::uint32_t CircuitBreaker::consecutive_successes() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return consecutive_successes_;
}

std::uint64_t CircuitBreaker::total_checks() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return total_checks_;
}

std::uint64_t CircuitBreaker::total_failures() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return total_failures_;
}

// v3.3.0 突破4: 连续熔断次数 getter
std::uint32_t CircuitBreaker::consecutive_opens() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return consecutive_opens_;
}

// v3.3.0 突破4: 实际生效的 cooldown getter（含指数退避）
std::chrono::milliseconds CircuitBreaker::effective_cooldown() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return effective_cooldown_locked();
}

// ============================================================================
// 默认健康探测
// ============================================================================

HealthProbeResult default_health_probe(const base::RelayUrl &relay_url) {
    HealthProbeResult result;
    auto start = std::chrono::steady_clock::now();

    std::string host = relay_url.host();
    std::uint16_t port = relay_url.port();
    if (port == 0) {
        // 默认端口
        if (relay_url.scheme() == "https") port = 443;
        else port = 80;
    }

#ifdef _WIN32
    // v1.7.0.6 (C8 fix): 用 std::call_once 全局初始化 WSA，避免每次 probe 都
    // WSAStartup/WSACleanup 导致引用计数失衡（与其他模块的 WSA 生命周期冲突）
    WSADATA wsaData;
    static std::once_flag wsa_flag;
    std::call_once(wsa_flag, []() {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
    });
#endif

    // 解析主机名
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *addr_info = nullptr;
    int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &addr_info);
    if (rc != 0 || addr_info == nullptr) {
        result.success = false;
        result.error_message = "getaddrinfo failed";
        return result;
    }

    // 创建 socket 并连接
#ifdef _WIN32
    SOCKET sock = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(addr_info);
        result.success = false;
        result.error_message = "socket failed";
        return result;
    }
#else
    int sock = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(addr_info);
        result.success = false;
        result.error_message = "socket failed";
        return result;
    }
#endif

    // 设置非阻塞 + 超时（简单实现，5 秒超时）
#ifdef _WIN32
    DWORD timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    int connect_rc = connect(sock, addr_info->ai_addr, (int)addr_info->ai_addrlen);

    auto end = std::chrono::steady_clock::now();
    auto rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

#ifdef _WIN32
    if (connect_rc == SOCKET_ERROR) {
        closesocket(sock);
        freeaddrinfo(addr_info);
        result.success = false;
        result.error_message = "connect failed";
        return result;
    }
    closesocket(sock);
    freeaddrinfo(addr_info);
#else
    if (connect_rc < 0) {
        ::close(sock);
        freeaddrinfo(addr_info);
        result.success = false;
        result.error_message = "connect failed";
        return result;
    }
    ::close(sock);
    freeaddrinfo(addr_info);
#endif

    result.success = true;
    result.rtt = rtt_ms;
    return result;
}

// ============================================================================
// RelayPool 实现
// ============================================================================

RelayPool::RelayPool(RelayPoolConfig config)
    : config_(std::move(config)), probe_(default_health_probe) {}

RelayPool::RelayPool(RelayPoolConfig config, HealthProbeCallback probe)
    : config_(std::move(config)), probe_(std::move(probe)) {}

// v1.7.0.6 (H2-2 fix): 析构时停止后台健康检查线程
RelayPool::~RelayPool() {
    stop_health_check_thread();
}

void RelayPool::start_health_check_thread() {
    // v1.7.0.6 (H2-2 fix): 后台周期性健康检查
    // 线程按 config_.check_interval 周期调用 check_all_sync()
    // 池为空时线程自动退出（避免空转），再次调用本方法可重启
    if (health_thread_running_.exchange(true)) {
        return;  // 已在运行
    }
    health_thread_ = std::thread([this]() {
        while (health_thread_running_.load()) {
            std::unique_lock<std::mutex> lk(health_mu_);
            // 等待间隔或停止信号
            health_cv_.wait_for(lk, config_.check_interval, [this]() {
                return !health_thread_running_.load();
            });
            if (!health_thread_running_.load()) break;

            // 池为空时退出（避免空转），但保留 running_ 标志以便外部感知
            {
                std::lock_guard<std::mutex> pool_lk(mutex_);
                if (entries_.empty()) {
                    break;  // 池空，线程退出
                }
            }

            try {
                check_all_sync();
            } catch (...) {
                // 探测异常不应中断后台线程
            }
        }
        health_thread_running_.store(false);
    });
}

void RelayPool::stop_health_check_thread() {
    if (!health_thread_running_.exchange(false)) {
        return;  // 未运行
    }
    health_cv_.notify_all();
    if (health_thread_.joinable()) {
        health_thread_.join();
    }
}

void RelayPool::add_relay(base::RelayUrl url, bool pinned) {
    std::lock_guard<std::mutex> lock(mutex_);
    // 去重
    for (auto &e : entries_) {
        if (e->url == url) {
            if (pinned) e->pinned = true;
            return;
        }
    }
    if (entries_.size() >= config_.max_relays) {
        // nn-M7 (v1.7.0.8): 移除最差的一个非 pinned（score 最低）。
        // 修复：原比较器 `a->score() < b->score()` 配合 max_element 选中 score
        // 最大（最健康）的元素，与"淘汰最差"相反，导致池质量持续下降。
        // 现反转 score 比较：max_element 选中 score 最小的（最差）非 pinned 元素。
        // pinned 语义不变：pinned 视为"小于"非 pinned，不被 max_element 选中。
        auto worst = std::max_element(
            entries_.begin(), entries_.end(),
            [](const std::unique_ptr<RelayEntry> &a, const std::unique_ptr<RelayEntry> &b) {
                if (a->pinned && !b->pinned) return true;
                if (!a->pinned && b->pinned) return false;
                return a->score() > b->score();
            });
        if (worst != entries_.end() && !(*worst)->pinned) {
            // 同时移除对应的熔断器（按索引同步）
            std::size_t idx = std::distance(entries_.begin(), worst);
            if (idx < breakers_.size()) {
                breakers_.erase(breakers_.begin() + idx);
            }
            entries_.erase(worst);
        }
    }
    auto entry = std::make_unique<RelayEntry>(url);
    entry->pinned = pinned;
    entries_.push_back(std::move(entry));
    breakers_.push_back(std::make_unique<CircuitBreaker>(config_.breaker_config));
}

bool RelayPool::remove_relay(const base::RelayUrl &url) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if ((*it)->url == url) {
            if ((*it)->pinned) return false;
            // 同步移除对应熔断器（按索引）
            std::size_t idx = std::distance(entries_.begin(), it);
            if (idx < breakers_.size()) {
                breakers_.erase(breakers_.begin() + idx);
            }
            entries_.erase(it);
            return true;
        }
    }
    return false;
}

std::vector<RelayEntry> RelayPool::get_all_relays() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RelayEntry> result;
    result.reserve(entries_.size());
    for (const auto &e : entries_) {
        result.push_back(*e);
    }
    return result;
}

std::vector<RelayEntry> RelayPool::get_usable_relays() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RelayEntry> result;
    for (const auto &e : entries_) {
        if (e->is_usable()) {
            result.push_back(*e);
        }
    }
    // v2.0 Phase 1：使用多维 score 排序（含跨区域惩罚），与 select_best 一致
    const auto local = config_.local_region;
    const auto &w = config_.score_weights;
    std::sort(result.begin(), result.end(),
        [local, &w](const RelayEntry &a, const RelayEntry &b) {
            return a.score(local, w) < b.score(local, w);
        });
    return result;
}

std::optional<RelayEntry> RelayPool::select_best() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (entries_.empty()) return std::nullopt;

    // v2.0 Phase 1 交付物 5：启用级联选择且已知本地区域时，走区域→骨干→全局降级
    if (config_.enable_cascading_select && config_.local_region != GeoRegion::Unknown) {
        // 首次选择或活跃集耗尽后重建缓存
        // 缓存保证 failover 时按原始排序推进，不受失败后 score 变化影响
        if (cached_active_set_.empty() && current_active_idx_ == 0) {
            cached_active_set_ = select_cascading_locked(config_.active_set_size);
        }
        if (!cached_active_set_.empty() && current_active_idx_ < cached_active_set_.size()) {
            return cached_active_set_[current_active_idx_];
        }
        // 缓存为空或索引越界 → 重新计算
        auto cascading = select_cascading_locked(1);
        if (!cascading.empty()) return cascading.front();
        return std::nullopt;
    }

    // v2.0 Phase 1：多维选择 — filter(usable, load) → sort(score) → take best
    // 三级降级：
    //   1) usable 且 load_percent <= load_filter_threshold
    //   2) usable（忽略 load 阈值，全池过载时）
    //   3) 全部（含 Unknown/Unhealthy，初始未探测或全池故障时向后兼容）
    auto score_fn = [this](const RelayEntry &e) {
        return e.score(config_.local_region, config_.score_weights);
    };

    auto pick_best = [&](auto &&filter) -> std::optional<RelayEntry> {
        const RelayEntry *best = nullptr;
        double best_score = 0;
        for (const auto &e : entries_) {
            if (!filter(*e)) continue;
            double s = score_fn(*e);
            if (best == nullptr || s < best_score) {
                best = e.get();
                best_score = s;
            }
        }
        if (best) return *best;
        return std::nullopt;
    };

    // 第一级：usable + load 未超阈值
    auto r = pick_best([&](const RelayEntry &e) {
        return e.is_usable() && e.load_percent <= config_.load_filter_threshold;
    });
    if (r) return r;

    // 第二级：usable（忽略 load）
    r = pick_best([&](const RelayEntry &e) { return e.is_usable(); });
    if (r) return r;

    // 第三级：全部（向后兼容初始 Unknown 状态）
    r = pick_best([&](const RelayEntry &) { return true; });
    return r;
}

std::optional<base::RelayUrl> RelayPool::select_best_url() const {
    auto best = select_best();
    if (!best) return std::nullopt;
    return best->url;
}

std::vector<RelayEntry> RelayPool::get_active_set() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (entries_.empty()) return {};

    // v2.0 Phase 1 交付物 5：启用级联选择时走区域→骨干→全局降级
    if (config_.enable_cascading_select && config_.local_region != GeoRegion::Unknown) {
        // 同步填充缓存（select_best 与 get_active_set 共享缓存，保证 failover 一致性）
        if (cached_active_set_.empty() && current_active_idx_ == 0) {
            cached_active_set_ = select_cascading_locked(config_.active_set_size);
        }
        if (!cached_active_set_.empty()) {
            return cached_active_set_;
        }
        return select_cascading_locked(config_.active_set_size);
    }

    const auto local = config_.local_region;
    const auto &w = config_.score_weights;
    auto score_fn = [local, &w](const RelayEntry &e) { return e.score(local, w); };

    // 收集候选并按 score 升序排序
    std::vector<const RelayEntry *> sorted_entries;
    sorted_entries.reserve(entries_.size());
    for (const auto &e : entries_) sorted_entries.push_back(e.get());
    std::sort(sorted_entries.begin(), sorted_entries.end(),
        [&](const RelayEntry *a, const RelayEntry *b) { return score_fn(*a) < score_fn(*b); });

    // 三级降级过滤（与 select_best 一致）
    std::vector<RelayEntry> result;
    auto take_top = [&](auto &&filter) -> bool {
        for (const auto *e : sorted_entries) {
            if (!filter(*e)) continue;
            result.push_back(*e);
            if (result.size() >= config_.active_set_size) return true;
        }
        return !result.empty();
    };

    // 第一级：usable + load 未超阈值
    if (take_top([&](const RelayEntry &e) {
            return e.is_usable() && e.load_percent <= config_.load_filter_threshold;
        })) {
        return result;
    }

    // 第二级：usable（忽略 load）
    if (take_top([&](const RelayEntry &e) { return e.is_usable(); })) {
        return result;
    }

    // 第三级：全部
    take_top([&](const RelayEntry &) { return true; });
    return result;
}

void RelayPool::set_local_region(GeoRegion region) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.local_region = region;
}

bool RelayPool::set_relay_metrics(const base::RelayUrl &url,
                                  int load_percent,
                                  int uplink_bps,
                                  GeoRegion region,
                                  int geo_distance_km) {
    std::lock_guard<std::mutex> lock(mutex_);
    RelayEntry *entry = find_entry(url);
    if (entry == nullptr) return false;
    if (load_percent >= 0) entry->load_percent = load_percent;
    if (uplink_bps >= 0) entry->uplink_bps = uplink_bps;
    if (region != GeoRegion::Unknown) entry->region = region;
    if (geo_distance_km >= 0) entry->geo_distance_km = geo_distance_km;
    return true;
}

// v2.0 Phase 1 交付物 5：层级化 Relay 架构 实现 ============================

bool RelayPool::set_relay_role(const base::RelayUrl &url, RelayRole role) {
    std::lock_guard<std::mutex> lock(mutex_);
    RelayEntry *entry = find_entry(url);
    if (entry == nullptr) return false;
    entry->role = role;
    return true;
}

std::size_t RelayPool::update_load_reports(const std::vector<RelayLoadReport> &reports) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t updated = 0;
    for (const auto &report : reports) {
        RelayEntry *entry = find_entry(report.url);
        if (entry == nullptr) continue;
        entry->role = report.role;
        entry->region = report.region;
        entry->load_percent = report.load_percent;
        entry->uplink_bps = report.uplink_bps;
        // connections / bytes_in / bytes_out 不持久化到 RelayEntry
        // （RelayEntry 是节点视角的候选池，不维护 Relay 服务端累计指标）
        ++updated;
    }
    return updated;
}

// ============================================================================
// V3-B: 跨域感知选择（协议规范 §5.2.2）
// ============================================================================
std::optional<RelayEntry> RelayPool::select_for_cross_domain() const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto local = config_.local_region;
    const auto &w = config_.score_weights;
    auto score_fn = [local, &w](const RelayEntry &e) { return e.score(local, w); };

    // 第一级：骨干 Backbone Relay（跨域可达，usable + load 过滤）
    std::vector<const RelayEntry *> tier;
    tier.reserve(entries_.size());
    for (const auto &e : entries_) {
        if (e->role == RelayRole::Backbone
            && e->is_usable()
            && e->load_percent <= config_.load_filter_threshold) {
            tier.push_back(e.get());
        }
    }

    // 第二级降级：全骨干不可用 → 区域 Region Relay 兜底（跨域穿透失败概率高，
    // 但骨干全挂时仍需提供回退路径，避免跨域连接无 Relay 可用）
    if (tier.empty()) {
        for (const auto &e : entries_) {
            if (e->role == RelayRole::Region && e->is_usable()) {
                tier.push_back(e.get());
            }
        }
    }

    // 第三级降级：全部 usable（忽略 load 阈值，全池过载时保证返回最优候选）
    if (tier.empty()) {
        for (const auto &e : entries_) {
            if (e->is_usable()) tier.push_back(e.get());
        }
    }

    if (tier.empty()) return std::nullopt;

    // 按 score 升序排序，取最优（score 越低越优：健康度高、RTT 低、负载低、距离近）
    std::sort(tier.begin(), tier.end(),
              [&](const RelayEntry *a, const RelayEntry *b) { return score_fn(*a) < score_fn(*b); });
    return *tier.front();
}

void RelayPool::set_cross_domain_backbone_relays(const std::vector<base::RelayUrl> &backbone_urls) {
    std::lock_guard<std::mutex> lock(mutex_);

    // 复用 add_relay 的淘汰逻辑：池满时移除 score 最差的非 pinned 条目
    auto evict_worst_if_full_locked = [this]() {
        if (entries_.size() < config_.max_relays) return;
        auto worst = std::max_element(
            entries_.begin(), entries_.end(),
            [](const std::unique_ptr<RelayEntry> &a, const std::unique_ptr<RelayEntry> &b) {
                // pinned 视为"小于"非 pinned，不被选中淘汰
                if (a->pinned && !b->pinned) return true;
                if (!a->pinned && b->pinned) return false;
                // 反转 score：max_element 选中 score 最小（最差）的非 pinned
                return a->score() > b->score();
            });
        if (worst != entries_.end() && !(*worst)->pinned) {
            std::size_t idx = std::distance(entries_.begin(), worst);
            if (idx < breakers_.size()) {
                breakers_.erase(breakers_.begin() + idx);
            }
            entries_.erase(worst);
        }
    };

    for (const auto &url : backbone_urls) {
        RelayEntry *entry = find_entry(url);
        if (entry == nullptr) {
            // 不存在则新增：pin + role=Backbone
            evict_worst_if_full_locked();
            auto new_entry = std::make_unique<RelayEntry>(url);
            new_entry->pinned = true;
            new_entry->role = RelayRole::Backbone;
            entries_.push_back(std::move(new_entry));
            breakers_.push_back(std::make_unique<CircuitBreaker>(config_.breaker_config));
        } else {
            // 已存在：仅更新 role/pinned，不重复入池
            entry->pinned = true;
            entry->role = RelayRole::Backbone;
        }
    }
}

void RelayPool::set_failover_callback(FailoverCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    failover_callback_ = std::move(cb);
}

void RelayPool::set_active_set_exhausted_callback(ActiveSetExhaustedCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    exhausted_callback_ = std::move(cb);
}

std::vector<RelayEntry> RelayPool::select_cascading_locked(std::size_t want_count) const {
    // 调用方已持 mutex_
    // 级联顺序：
    //   第一级：本区域 Region Relay（usable + load + region==local + role==Region）
    //   第二级：骨干 Backbone Relay（usable + load + role==Backbone）
    //   第三级：全局 Region Relay（usable + load，跨区域）
    //   第四级：全局 usable（忽略 load，全池过载时）
    //   第五级：全部（向后兼容初始 Unknown 状态）
    //
    // 每一级内部按 score 升序排序，跨级合并后取前 want_count 个。
    // 实际策略：第一级填满 want_count 即返回；不足才进入下一级补足。

    const auto local = config_.local_region;
    const auto &w = config_.score_weights;
    auto score_fn = [local, &w](const RelayEntry &e) { return e.score(local, w); };

    std::vector<RelayEntry> result;
    if (want_count == 0) return result;
    result.reserve(want_count);

    auto take_top_filtered = [&](auto &&filter) {
        // 收集本级候选并排序
        std::vector<const RelayEntry *> tier;
        tier.reserve(entries_.size());
        for (const auto &e : entries_) {
            if (filter(*e)) tier.push_back(e.get());
        }
        std::sort(tier.begin(), tier.end(),
            [&](const RelayEntry *a, const RelayEntry *b) { return score_fn(*a) < score_fn(*b); });
        // 补足到 want_count（不重复：URL 去重）
        for (const auto *e : tier) {
            // 检查是否已在 result 中（按 URL 去重）
            bool dup = false;
            for (const auto &r : result) {
                if (r.url == e->url) { dup = true; break; }
            }
            if (dup) continue;
            result.push_back(*e);
            if (result.size() >= want_count) return true;
        }
        return false;
    };

    // 第一级：本区域 Region Relay
    if (take_top_filtered([&](const RelayEntry &e) {
            return e.role == RelayRole::Region
                && e.region == local
                && e.is_usable()
                && e.load_percent <= config_.load_filter_threshold;
        })) {
        return result;
    }

    // 第二级：骨干 Backbone Relay（Backbone 区域与任意区域不算跨区域，由 is_cross_region 处理）
    if (take_top_filtered([&](const RelayEntry &e) {
            return e.role == RelayRole::Backbone
                && e.is_usable()
                && e.load_percent <= config_.load_filter_threshold;
        })) {
        return result;
    }

    // 第三级：全局 Region Relay（跨区域，仍走负载过滤）
    if (take_top_filtered([&](const RelayEntry &e) {
            return e.role == RelayRole::Region
                && e.is_usable()
                && e.load_percent <= config_.load_filter_threshold;
        })) {
        return result;
    }

    // 第四级：全局 usable（忽略 load 阈值，全池过载时）
    if (take_top_filtered([&](const RelayEntry &e) { return e.is_usable(); })) {
        return result;
    }

    // 第五级：全部（向后兼容初始 Unknown 状态）
    take_top_filtered([&](const RelayEntry &) { return true; });
    return result;
}

std::optional<base::RelayUrl> RelayPool::advance_active_idx_locked(const base::RelayUrl &failed_url) {
    // 调用方已持 mutex_
    // 主用失败超阈值时调用：推进活跃集索引到下一个候选
    //
    // 使用缓存活跃集（cached_active_set_），避免失败后 score 变化导致活跃集重排。
    // 失败的 relay 在原始排序中的位置不变，直接推进 current_active_idx_ + 1。

    // 缓存为空时（select_best 未被调用过）现场计算
    if (cached_active_set_.empty()) {
        cached_active_set_ = select_cascading_locked(config_.active_set_size);
    }

    if (cached_active_set_.empty()) {
        // 活跃集耗尽，触发回调（锁外调用由调用方处理）
        current_active_idx_ = 0;
        return std::nullopt;
    }

    // 推进到下一个候选
    std::size_t new_idx = current_active_idx_ + 1;

    // 推进超过活跃集大小 → 活跃集耗尽
    if (new_idx >= cached_active_set_.size()) {
        current_active_idx_ = 0;
        cached_active_set_.clear();  // 清空缓存，下次 select_best 重建
        return std::nullopt;  // 调用方触发 exhausted_callback_
    }

    current_active_idx_ = new_idx;
    return cached_active_set_[new_idx].url;
}

void RelayPool::check_all_sync() {
    std::vector<base::RelayUrl> urls;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        urls.reserve(entries_.size());
        for (const auto &e : entries_) {
            urls.push_back(e->url);
        }
    }

    // 并行探测
    std::vector<std::future<HealthProbeResult>> futures;
    futures.reserve(urls.size());
    for (const auto &url : urls) {
        futures.push_back(std::async(std::launch::async, [this, url]() {
            return check_one(url);
        }));
    }

    for (auto &f : futures) {
        // nn-M9 (v1.7.0.8): wait_for 带超时，避免单个 relay 探测卡死
        // （connect 阻塞 / STUN 无响应 / SO_RCVTIMEO 未生效）导致整个后台
        // 健康检查线程停摆。超时后跳过该 relay，future 析构时后台任务仍可能运行。
        if (f.wait_for(std::chrono::seconds(10)) != std::future_status::ready) {
            LINOH_WARN("RelayPool: health check timeout (10s) for one relay, skipping");
        }
    }
}

std::future<void> RelayPool::check_all_async() {
    return std::async(std::launch::async, [this]() { check_all_sync(); });
}

HealthProbeResult RelayPool::check_one(const base::RelayUrl &url) {
    HealthProbeResult result;
    if (!probe_) {
        result.success = false;
        result.error_message = "no probe callback";
        return result;
    }

    result = probe_(url);

    std::lock_guard<std::mutex> lock(mutex_);
    RelayEntry *entry = find_entry(url);
    if (entry == nullptr) return result;

    apply_probe_result(*entry, result);
    return result;
}

void RelayPool::record_success(const base::RelayUrl &url) {
    std::lock_guard<std::mutex> lock(mutex_);
    RelayEntry *entry = find_entry(url);
    CircuitBreaker *breaker = find_breaker(url);
    if (entry) {
        entry->consecutive_failures = 0;
        entry->consecutive_successes++;
        entry->total_checks++;
        if (entry->health == RelayHealth::Unhealthy || entry->health == RelayHealth::CircuitOpen) {
            entry->health = RelayHealth::Degraded;
        }
    }
    if (breaker) breaker->record_success();
}

void RelayPool::record_failure(const base::RelayUrl &url) {
    // v2.0 Phase 1 交付物 5：主用失败超阈值时触发故障切换
    // 锁内更新状态 + 收集回调到局部变量，锁外调用防重入（锁内不调回调规范）
    FailoverCallback fo_cb_copy;
    ActiveSetExhaustedCallback ex_cb_copy;
    base::RelayUrl from_url;
    base::RelayUrl to_url;
    bool trigger_failover = false;
    bool trigger_exhausted = false;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        RelayEntry *entry = find_entry(url);
        CircuitBreaker *breaker = find_breaker(url);
        if (entry) {
            entry->consecutive_failures++;
            entry->consecutive_successes = 0;
            entry->total_failures++;
            if (entry->consecutive_failures >= config_.breaker_config.failure_threshold) {
                entry->health = RelayHealth::Unhealthy;
            } else if (entry->consecutive_failures >= 2) {
                entry->health = RelayHealth::Degraded;
            }

            // v2.0 交付物 5：主用连续失败达 failover_failure_threshold → 推进活跃集索引
            if (entry->consecutive_failures == config_.failover_failure_threshold) {
                from_url = url;
                auto new_primary = advance_active_idx_locked(url);
                if (new_primary) {
                    to_url = *new_primary;
                    last_primary_ = *new_primary;
                    last_failover_time_ = std::chrono::system_clock::now();
                    trigger_failover = true;
                    fo_cb_copy = failover_callback_;
                } else {
                    trigger_exhausted = true;
                    ex_cb_copy = exhausted_callback_;
                }
            }
        }
        if (breaker) breaker->record_failure();
    }

    // 锁外调用回调（防重入死锁）
    if (trigger_failover && fo_cb_copy) {
        fo_cb_copy(from_url, to_url, "failover_failure_threshold_reached");
    }
    if (trigger_exhausted && ex_cb_copy) {
        ex_cb_copy();
    }
}

std::optional<base::RelayUrl> RelayPool::current_primary() const {
    return select_best_url();
}

std::size_t RelayPool::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

RelayEntry *RelayPool::find_entry(const base::RelayUrl &url) {
    for (auto &e : entries_) {
        if (e->url == url) return e.get();
    }
    return nullptr;
}

const RelayEntry *RelayPool::find_entry(const base::RelayUrl &url) const {
    for (auto &e : entries_) {
        if (e->url == url) return e.get();
    }
    return nullptr;
}

CircuitBreaker *RelayPool::find_breaker(const base::RelayUrl &url) {
    std::size_t idx = 0;
    for (auto &e : entries_) {
        if (e->url == url) {
            if (idx < breakers_.size()) return breakers_[idx].get();
            return nullptr;
        }
        idx++;
    }
    return nullptr;
}

void RelayPool::apply_probe_result(RelayEntry &entry, const HealthProbeResult &result) {
    entry.last_check = std::chrono::system_clock::now();
    entry.total_checks++;

    // v2.0 Phase 1：探测结果携带的负载/带宽元数据同步到 entry
    // （增强型探测器可填充，默认 TCP connect 探测保持 0）
    if (result.load_percent > 0) entry.load_percent = result.load_percent;
    if (result.uplink_bps > 0) entry.uplink_bps = result.uplink_bps;

    if (result.success) {
        entry.last_rtt = result.rtt;
        entry.consecutive_failures = 0;
        entry.consecutive_successes++;

        if (result.rtt > config_.degraded_rtt_threshold) {
            entry.health = RelayHealth::Degraded;
        } else {
            entry.health = RelayHealth::Healthy;
        }
    } else {
        entry.consecutive_failures++;
        entry.consecutive_successes = 0;
        entry.total_failures++;

        if (entry.consecutive_failures >= config_.breaker_config.failure_threshold) {
            entry.health = RelayHealth::Unhealthy;
        } else if (entry.consecutive_failures >= 2) {
            entry.health = RelayHealth::Degraded;
        }
    }
}

std::optional<base::RelayUrl> RelayPool::do_failover() {
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_failover_time_);
    if (elapsed < config_.failover_min_interval) {
        return last_primary_;
    }

    auto best = select_best_url();
    if (!best) return std::nullopt;

    if (!(last_primary_ == *best)) {
        last_primary_ = *best;
        last_failover_time_ = now;
    }
    return best;
}

// ============================================================================
// FailoverController 实现
// ============================================================================

FailoverController::FailoverController(std::shared_ptr<RelayPool> pool,
                                       FailoverCallback callback)
    : pool_(std::move(pool)), callback_(std::move(callback)) {}

std::optional<base::RelayUrl> FailoverController::trigger_failover(const std::string &reason) {
    if (!enabled_ || !pool_) return std::nullopt;

    auto new_primary = pool_->select_best_url();
    if (!new_primary) return std::nullopt;

    // 与自己维护的 last_primary_ 比较
    bool changed = !has_last_primary_ || !(last_primary_ == *new_primary);
    if (changed) {
        FailoverEvent event;
        event.from_url = has_last_primary_ ? last_primary_ : base::RelayUrl{};
        event.to_url = *new_primary;
        event.timestamp = std::chrono::system_clock::now();
        event.reason = reason;

        // nn-M8 (v1.7.0.8): 锁内更新状态，锁外调用 callback。
        // 原实现锁内调 callback_，若回调调用 get_history/trigger_failover 自身
        // 会重入 mutex_ 死锁；回调阻塞也会长时间持锁影响其他 failover 请求。
        FailoverCallback cb_copy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            history_.push_back(event);
            last_primary_ = *new_primary;
            has_last_primary_ = true;
            cb_copy = callback_;
        }
        if (cb_copy) cb_copy(event);
    }

    return new_primary;
}

std::vector<FailoverEvent> FailoverController::get_history() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_;
}

void FailoverController::clear_history() {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.clear();
}

} // namespace linoh::nat
