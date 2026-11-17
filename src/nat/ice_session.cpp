// ice_session.cpp — P5-D-2 ICE 风格连接检查 + 提名实现

#include "linoh/nat/ice_session.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <vector>

namespace linoh::nat {

// ============================================================================
// CandidatePair 方法
// ============================================================================

std::string CandidatePair::to_string() const {
    std::ostringstream oss;
    oss << "CandidatePair{state=" << pair_state_name(state)
        << ", prio=" << priority
        << ", nominated=" << (nominated ? "true" : "false")
        << ", rtt=" << rtt.count() << "ms"
        << ", local=" << local.to_string()
        << ", remote=" << remote.to_string()
        << "}";
    return oss.str();
}

// ============================================================================
// 默认连接检查器
// ============================================================================

ConnectivityChecker default_connectivity_checker() {
    return [](const CandidatePair &pair,
              std::chrono::milliseconds timeout)
           -> std::future<std::pair<bool, std::chrono::milliseconds>> {
        return std::async(std::launch::async, [pair, timeout]() {
            // 占位实现：默认失败
            (void)pair;
            (void)timeout;
            return std::make_pair(false, std::chrono::milliseconds(0));
        });
    };
}

// ============================================================================
// IceSession 实现
// ============================================================================

IceSession::IceSession(std::vector<Candidate> local_candidates,
                        std::vector<Candidate> remote_candidates,
                        IceSessionConfig config)
    : local_candidates_(std::move(local_candidates)),
      remote_candidates_(std::move(remote_candidates)),
      config_(std::move(config)),
      checker_(default_connectivity_checker()),
      task_pool_(std::make_unique<util::TaskPool>(
          static_cast<std::size_t>(std::max<std::uint32_t>(config_.max_parallel_checks, 4)))) {
    form_candidate_pairs();
}

IceSession::IceSession(std::vector<Candidate> local_candidates,
                        std::vector<Candidate> remote_candidates,
                        IceSessionConfig config,
                        ConnectivityChecker checker)
    : local_candidates_(std::move(local_candidates)),
      remote_candidates_(std::move(remote_candidates)),
      config_(std::move(config)),
      checker_(std::move(checker)),
      task_pool_(std::make_unique<util::TaskPool>(
          static_cast<std::size_t>(std::max<std::uint32_t>(config_.max_parallel_checks, 4)))) {
    form_candidate_pairs();
}

bool IceSession::is_address_family_compatible(const Candidate &a, const Candidate &b) {
    // 同地址族兼容
    bool a_v6 = is_ipv6(a.tuple.local_addr.host);
    bool b_v6 = is_ipv6(b.tuple.local_addr.host);
    return a_v6 == b_v6;
}

bool IceSession::is_ipv6(const std::string &host) {
    // 简单判断：包含冒号为 IPv6
    return host.find(':') != std::string::npos;
}

void IceSession::form_candidate_pairs() {
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    form_candidate_pairs_locked();
}

// nn-M5 (v1.7.0.8): 锁内实现，调用方必须已持有 pairs_mutex_。
// 拆分此 helper 让 add_local_candidate / add_remote_candidate 能在同一把锁内
// 完成"修改 candidates_ + 重建 pairs_"，消除原实现的竞争窗口。
void IceSession::form_candidate_pairs_locked() {
    pairs_.clear();

    for (const auto &local : local_candidates_) {
        for (const auto &remote : remote_candidates_) {
            if (!is_address_family_compatible(local, remote)) continue;

            // P0-G5-2: 过滤 relay↔direct 候选对（避免 relay→direct NAT 穿透失败浪费）
            if (config_.skip_relay_to_non_relay_connections) {
                bool local_relay = needs_relay(local);
                bool remote_relay = needs_relay(remote);
                if (local_relay != remote_relay) continue;  // 一端 relay 一端 direct
            }

            CandidatePair pair(local, remote);
            pair.priority = compute_pair_priority(
                local.priority, remote.priority, config_.role);
            pairs_.push_back(std::move(pair));
        }
    }

    sort_pairs_by_priority(pairs_);
}

std::vector<CandidatePair> IceSession::candidate_pairs() const {
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    return pairs_;
}

std::future<bool> IceSession::start_connectivity_checks() {
    return std::async(std::launch::async, [this]() {
        return start_connectivity_checks_sync();
    });
}

bool IceSession::start_connectivity_checks_sync() {
    if (completed_.load()) {
        // nn-M3 (v1.7.0.8): 原实现在锁外读 nominated_pair_，与 nominate_best /
        // nominate_pair 的提名写入竞争（data race on std::optional）。
        // 同时 succeeded_pairs() 内部自取锁，与 nominated_pair_ 读取之间存在
        // TOCTOU 窗口。改为在同一把 pairs_mutex_ 下原子地检查两项状态。
        std::lock_guard<std::mutex> lk(pairs_mutex_);
        // nn-M4 (v1.7.0.8): 顺便清理已完成的 pending_futures_，避免长期累积。
        prune_pending_futures_locked();
        bool has_succeeded = false;
        for (const auto &p : pairs_) {
            if (p.state == CandidatePairState::Succeeded) {
                has_succeeded = true;
                break;
            }
        }
        return nominated_pair_.has_value() || has_succeeded;
    }

    // nn-M4 (v1.7.0.8): 进入新一轮检查前清理上一轮残留的已完成 future。
    {
        std::lock_guard<std::mutex> lk(pairs_mutex_);
        prune_pending_futures_locked();
    }

    auto start = std::chrono::steady_clock::now();
    auto deadline = start + config_.timeout;

    // 收集所有 Waiting 状态的候选对
    std::vector<std::size_t> waiting_indices;
    {
        std::lock_guard<std::mutex> lk(pairs_mutex_);
        // P0-G5-1: 全 relay 候选对跳过 STUN 检查，直接标记 Succeeded
        // （relay 路径已保证可达，无需初始连接检查）
        if (config_.presume_writable_when_fully_relayed) {
            for (auto &p : pairs_) {
                if (p.state == CandidatePairState::Waiting &&
                    needs_relay(p.local) && needs_relay(p.remote)) {
                    p.state = CandidatePairState::Succeeded;
                    p.rtt = std::chrono::milliseconds(0);
                }
            }
        }
        for (std::size_t i = 0; i < pairs_.size(); ++i) {
            if (pairs_[i].state == CandidatePairState::Waiting ||
                pairs_[i].state == CandidatePairState::Frozen) {
                waiting_indices.push_back(i);
            }
        }
    }

    if (waiting_indices.empty()) {
        completed_.store(true);
        return false;
    }

    // 并行检查（受 max_parallel_checks 限制）
    std::atomic<std::size_t> next_idx{0};
    std::atomic<bool> any_success{false};

    auto worker = [&]() {
        while (true) {
            std::size_t idx = next_idx.fetch_add(1);
            if (idx >= waiting_indices.size()) break;

            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) break;

            std::size_t pair_idx = waiting_indices[idx];
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);
            auto timeout = (std::min)(remaining, config_.request_timeout);

            CandidatePair pair_copy;
            {
                std::lock_guard<std::mutex> lk(pairs_mutex_);
                if (pairs_[pair_idx].state != CandidatePairState::Waiting &&
                    pairs_[pair_idx].state != CandidatePairState::Frozen) {
                    continue;
                }
                pairs_[pair_idx].state = CandidatePairState::InProgress;
                pairs_[pair_idx].last_check_time = now;
                pairs_[pair_idx].request_count++;
                pair_copy = pairs_[pair_idx];
            }

            try {
                auto fut = checker_(pair_copy, timeout);
                auto status = fut.wait_for(remaining);
                if (status == std::future_status::ready) {
                    auto [success, rtt] = fut.get();
                    std::lock_guard<std::mutex> lk(pairs_mutex_);
                    if (success) {
                        pairs_[pair_idx].state = CandidatePairState::Succeeded;
                        pairs_[pair_idx].rtt = rtt;
                        any_success.store(true);
                    } else {
                        pairs_[pair_idx].state = CandidatePairState::Failed;
                    }
                } else {
                    // nn-M4 (v1.7.0.8): 超时 future 不再 detach（detach 会累积独立
                    // 线程，且 detached 线程的 future 析构仍可能在后台阻塞，造成
                    // 线程泄漏 + 析构后访问已释放资源的风险）。
                    // 改为移入 pending_futures_（受 pairs_mutex_ 保护），由
                    // prune_pending_futures_locked() 定期清理已完成的 future，
                    // 析构时统一 wait_for 回收。
                    std::lock_guard<std::mutex> lk(pairs_mutex_);
                    pairs_[pair_idx].state = CandidatePairState::Failed;
                    pending_futures_.push_back(std::move(fut));
                }
            } catch (const std::exception &) {
                std::lock_guard<std::mutex> lk(pairs_mutex_);
                pairs_[pair_idx].state = CandidatePairState::Failed;
            }
        }
    };

    std::size_t worker_count = (std::min)(
        static_cast<std::size_t>(config_.max_parallel_checks),
        waiting_indices.size());
    std::vector<std::thread> threads;
    threads.reserve(worker_count);
    for (std::size_t i = 0; i < worker_count; ++i) {
        threads.emplace_back(worker);
    }
    for (auto &t : threads) t.join();

    // Controlling 角色自动提名
    if (any_success.load() && config_.enable_nomination &&
        config_.role == IceRole::Controlling) {
        nominate_best();
    }

    completed_.store(true);
    return any_success.load();
}

std::optional<CandidatePair> IceSession::nominate_best() {
    if (config_.role != IceRole::Controlling) {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lk(pairs_mutex_);

    // 筛选所有成功的候选对
    std::vector<const CandidatePair *> succeeded;
    for (const auto &p : pairs_) {
        if (p.state == CandidatePairState::Succeeded) {
            succeeded.push_back(&p);
        }
    }

    if (succeeded.empty()) {
        return std::nullopt;
    }

    // 按优先级或延迟选择最佳
    const CandidatePair *best = nullptr;
    if (config_.nominate_by_priority) {
        // pairs_ 已按 priority 降序排序，找第一个成功的
        for (const auto &p : pairs_) {
            if (p.state == CandidatePairState::Succeeded) {
                best = &p;
                break;
            }
        }
    } else {
        // 按 RTT 升序，找延迟最低的
        auto cmp = [](const CandidatePair *a, const CandidatePair *b) {
            return a->rtt < b->rtt;
        };
        best = *std::min_element(succeeded.begin(), succeeded.end(), cmp);
    }

    if (best == nullptr) return std::nullopt;

    // 标记提名的候选对
    for (auto &p : pairs_) {
        if (p == *best) {
            p.nominated = true;
            nominated_pair_ = p;
            return p;
        }
    }
    return std::nullopt;
}

bool IceSession::nominate_pair(const CandidatePair &pair) {
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    for (auto &p : pairs_) {
        if (p == pair) {
            if (p.state != CandidatePairState::Succeeded) {
                return false;  // 只能提名成功的候选对
            }
            p.nominated = true;
            nominated_pair_ = p;
            return true;
        }
    }
    return false;
}

void IceSession::trigger_check(const CandidatePair &pair) {
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    // 查找是否存在该候选对
    for (auto &p : pairs_) {
        if (p == pair) {
            // 已存在，若为 Frozen/Failed 重新触发
            if (p.state == CandidatePairState::Frozen ||
                p.state == CandidatePairState::Failed) {
                p.state = CandidatePairState::Waiting;
            }
            return;
        }
    }

    // 不存在，添加新的候选对
    CandidatePair new_pair = pair;
    new_pair.priority = compute_pair_priority(
        pair.local.priority, pair.remote.priority, config_.role);
    new_pair.state = CandidatePairState::Waiting;
    pairs_.push_back(std::move(new_pair));
    sort_pairs_by_priority(pairs_);
}

std::optional<CandidatePair> IceSession::nominated_pair() const {
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    return nominated_pair_;
}

std::vector<CandidatePair> IceSession::succeeded_pairs() const {
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    std::vector<CandidatePair> result;
    for (const auto &p : pairs_) {
        if (p.state == CandidatePairState::Succeeded) {
            result.push_back(p);
        }
    }
    return result;
}

std::vector<CandidatePair> IceSession::failed_pairs() const {
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    std::vector<CandidatePair> result;
    for (const auto &p : pairs_) {
        if (p.state == CandidatePairState::Failed) {
            result.push_back(p);
        }
    }
    return result;
}

void IceSession::reset() {
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    pairs_.clear();
    nominated_pair_.reset();
    completed_.store(false);
    // nn-M4 (v1.7.0.8): 顺手回收已完成的 pending_futures_，避免 reset+重跑
    // 循环中长期累积未清理的 future。未完成的保留，由析构或下次 prune 处理。
    prune_pending_futures_locked();
}

void IceSession::add_local_candidate(Candidate c) {
    // nn-M5 (v1.7.0.8): 原实现先无锁 push_back 到 local_candidates_，
    // 再调用 form_candidate_pairs()（内部取锁读 candidates_）。
    // 若并发调用 add_*_candidate 或与 form_candidate_pairs 竞争，
    // 会出现 candidates_ 容器 vector 扩容时的 data race + 迭代器失效。
    // 改为在同一把 pairs_mutex_ 内完成"push_back + 重建 pairs_"。
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    local_candidates_.push_back(std::move(c));
    form_candidate_pairs_locked();
}

void IceSession::add_remote_candidate(Candidate c) {
    // nn-M5 (v1.7.0.8): 同 add_local_candidate，锁内完成 push_back + 重建。
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    remote_candidates_.push_back(std::move(c));
    form_candidate_pairs_locked();
}

// P0-G5-3: 重新收集候选（配合 gather_continually，由上层周期调用）
void IceSession::regather_candidates(std::vector<Candidate> new_local,
                                     std::vector<Candidate> new_remote) {
    std::lock_guard<std::mutex> lk(pairs_mutex_);
    // 合并去重（Candidate::operator== 按 type + tuple 判等）
    for (auto &c : new_local) {
        if (std::find(local_candidates_.begin(), local_candidates_.end(), c)
            == local_candidates_.end()) {
            local_candidates_.push_back(std::move(c));
        }
    }
    for (auto &c : new_remote) {
        if (std::find(remote_candidates_.begin(), remote_candidates_.end(), c)
            == remote_candidates_.end()) {
            remote_candidates_.push_back(std::move(c));
        }
    }
    // 重建候选对（应用 G5-2 过滤 + 排序）
    form_candidate_pairs_locked();
}

// nn-M4 (v1.7.0.8): 清理 pending_futures_ 中已 ready 的 future。
// 调用方必须已持有 pairs_mutex_（与 pairs_ 同锁，避免多锁死锁）。
// 用 wait_for(zero) 非阻塞探测：已完成的回收，未完成的保留待下次清理。
void IceSession::prune_pending_futures_locked() {
    auto it = pending_futures_.begin();
    while (it != pending_futures_.end()) {
        if (it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            try { (void)it->get(); } catch (...) {}
            it = pending_futures_.erase(it);
        } else {
            ++it;
        }
    }
}

// nn-M4 (v1.7.0.8): 析构时对 pending_futures_ 做有界 wait_for 回收。
// 每个 future 最多等待 2 秒（足够 checker 完成 STUN 超时回收），
// 超时则放弃等待（future 析构会自行处理 std::async 任务的清理），
// 避免 IceSession 析构无限阻塞。
IceSession::~IceSession() {
    std::vector<std::future<std::pair<bool, std::chrono::milliseconds>>> leftover;
    {
        std::lock_guard<std::mutex> lk(pairs_mutex_);
        leftover.swap(pending_futures_);
    }
    for (auto &f : leftover) {
        if (f.valid()) {
            try {
                (void)f.wait_for(std::chrono::seconds(2));
            } catch (...) {}
        }
    }
    // leftover 析构：未完成的 std::async future 由析构阻塞等待（标准要求），
    // 但此时 checker lambda 已捕获 pair 副本，不依赖 IceSession 状态。
}

// ============================================================================
// 工具函数
// ============================================================================

void sort_pairs_by_priority(std::vector<CandidatePair> &pairs) {
    std::sort(pairs.begin(), pairs.end(),
              [](const CandidatePair &a, const CandidatePair &b) {
                  return a.priority > b.priority;  // 降序
              });
}

void sort_pairs_by_rtt(std::vector<CandidatePair> &pairs) {
    std::sort(pairs.begin(), pairs.end(),
              [](const CandidatePair &a, const CandidatePair &b) {
                  return a.rtt < b.rtt;  // 升序
              });
}

// P0-G5-4: 按历史成功率加权排序候选对
void sort_pairs_by_priority_with_history(
    std::vector<CandidatePair> &pairs,
    const std::function<double(const CandidatePair &)> &history_score,
    double history_weight) {
    // 综合评分 = priority * (1 - w) + history_score * w * priority
    // history_score 范围 [0.0, 1.0]，乘以 priority 保持量纲一致
    std::stable_sort(pairs.begin(), pairs.end(),
        [&](const CandidatePair &a, const CandidatePair &b) {
            double pa = static_cast<double>(a.priority);
            double pb = static_cast<double>(b.priority);
            double sa = pa * (1.0 - history_weight)
                      + history_score(a) * history_weight * pa;
            double sb = pb * (1.0 - history_weight)
                      + history_score(b) * history_weight * pb;
            return sa > sb;  // 降序
        });
}

PairStateCount count_pairs_by_state(const std::vector<CandidatePair> &pairs) {
    PairStateCount cnt;
    for (const auto &p : pairs) {
        switch (p.state) {
            case CandidatePairState::Waiting:    ++cnt.waiting; break;
            case CandidatePairState::InProgress: ++cnt.in_progress; break;
            case CandidatePairState::Succeeded:  ++cnt.succeeded; break;
            case CandidatePairState::Failed:     ++cnt.failed; break;
            case CandidatePairState::Frozen:     ++cnt.frozen; break;
        }
    }
    return cnt;
}

} // namespace linoh::nat
