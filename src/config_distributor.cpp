// config_distributor.cpp — 配置分发器实现（v2.1 Phase 2）
//
// 实现配置的本地管理、签名验证、CRDT 合并、gossip 传播、落后检测、热更新订阅、历史回滚。

#include "linoh/config_distributor.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <tuple>

#include "linoh/util/logging.hpp"

namespace linoh {

// ============================================================================
// 构造函数
// ============================================================================

ConfigDistributor::ConfigDistributor(NodeRegistry &registry,
                                     ControlPlaneConfig cfg,
                                     ClockFunc clock)
    : registry_(registry),
      config_(std::move(cfg)),
      clock_(clock ? std::move(clock) : ClockFunc([]() { return std::chrono::system_clock::now(); })) {}

// ============================================================================
// 本地配置操作
// ============================================================================

void ConfigDistributor::set_local(const std::string &key,
                                   const std::string &value,
                                   const base::SecretKey &signing_key) {
    std::string old_value;
    {
        std::lock_guard<std::mutex> lk(mu_);

        // 递增 epoch 和 version
        ++epoch_;
        ++version_counter_;

        ConfigEntry entry;
        entry.key = key;
        entry.value = value;
        entry.version = version_counter_;
        entry.updated_at = clock_();

        // 记录旧值（用于通知订阅者）
        auto it = entries_.find(key);
        if (it != entries_.end()) {
            old_value = it->second.value;
        }

        // 应用变更
        entries_[key] = entry;

        // 保存历史快照
        ConfigSnapshot snapshot;
        snapshot.epoch = epoch_;
        snapshot.created_at = clock_();
        snapshot.origin = signing_key.public_key();
        snapshot.entries.reserve(entries_.size());
        for (const auto &[k, e] : entries_) {
            snapshot.entries.push_back(e);
        }
        // 签名
        auto sig_data = snapshot.signing_data();
        auto sig = signing_key.sign(sig_data);
        std::memcpy(snapshot.signature.data(), sig.data(), 64);
        save_history_locked(snapshot);

        LINOH_INFO("ConfigDistributor: set_local key=%s value=%s epoch=%llu",
                   key.c_str(), value.c_str(),
                   static_cast<unsigned long long>(epoch_));
    }

    // 锁外通知订阅者
    notify_subscribers(key, old_value, value);
}

void ConfigDistributor::delete_local(const std::string &key,
                                     const base::SecretKey &signing_key) {
    std::string old_value;
    bool deleted = false;
    {
        std::lock_guard<std::mutex> lk(mu_);

        auto it = entries_.find(key);
        if (it == entries_.end()) return;  // 不存在，无需删除

        ++epoch_;

        old_value = it->second.value;
        entries_.erase(it);
        deleted = true;

        // 保存历史快照
        ConfigSnapshot snapshot;
        snapshot.epoch = epoch_;
        snapshot.created_at = clock_();
        snapshot.origin = signing_key.public_key();
        snapshot.entries.reserve(entries_.size());
        for (const auto &[k, e] : entries_) {
            snapshot.entries.push_back(e);
        }
        auto sig_data = snapshot.signing_data();
        auto sig = signing_key.sign(sig_data);
        std::memcpy(snapshot.signature.data(), sig.data(), 64);
        save_history_locked(snapshot);

        LINOH_INFO("ConfigDistributor: delete_local key=%s epoch=%llu",
                   key.c_str(), static_cast<unsigned long long>(epoch_));
    }

    // 锁外通知订阅者
    if (deleted) {
        notify_subscribers(key, old_value, "");  // 空字符串表示删除
    }
}

std::optional<std::string> ConfigDistributor::get_local(const std::string &key) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = entries_.find(key);
    if (it == entries_.end()) return std::nullopt;
    return it->second.value;
}

ConfigSnapshot ConfigDistributor::get_snapshot() const {
    std::lock_guard<std::mutex> lk(mu_);
    ConfigSnapshot snapshot;
    snapshot.epoch = epoch_;
    snapshot.created_at = clock_();
    snapshot.entries.reserve(entries_.size());
    for (const auto &[k, e] : entries_) {
        snapshot.entries.push_back(e);
    }
    return snapshot;
}

std::uint64_t ConfigDistributor::current_epoch() const noexcept {
    return epoch_;
}

// ============================================================================
// 配置同步（验证签名 + 应用 + 触发热更新）
// ============================================================================

bool ConfigDistributor::apply_snapshot(const ConfigSnapshot &snapshot,
                                        const base::PublicKey &orchestrator_pubkey) {
    // 验证签名（只读参数，不需要锁）
    auto sig_data = snapshot.signing_data();
    if (!verify_signature_locked(sig_data, snapshot.signature, orchestrator_pubkey)) {
        LINOH_WARN("ConfigDistributor: apply_snapshot signature verification failed (epoch=%llu)",
                   static_cast<unsigned long long>(snapshot.epoch));
        return false;
    }

    // 变更收集：(key, old_value, new_value)
    std::vector<std::tuple<std::string, std::string, std::string>> changes;

    {
        std::lock_guard<std::mutex> lk(mu_);

        // epoch 防回退
        if (snapshot.epoch <= epoch_) {
            LINOH_WARN("ConfigDistributor: apply_snapshot epoch rollback rejected "
                       "(current=%llu, snapshot=%llu)",
                       static_cast<unsigned long long>(epoch_),
                       static_cast<unsigned long long>(snapshot.epoch));
            return false;
        }

        // 收集旧值
        std::unordered_map<std::string, std::string> old_values;
        for (const auto &entry : entries_) {
            old_values[entry.first] = entry.second.value;
        }

        // 替换本地配置
        entries_.clear();
        for (const auto &entry : snapshot.entries) {
            entries_[entry.key] = entry;
            std::string old_val = old_values.count(entry.key) ? old_values[entry.key] : "";
            if (old_val != entry.value) {
                changes.emplace_back(entry.key, old_val, entry.value);
            }
            // 更新 version_counter
            if (entry.version > version_counter_) {
                version_counter_ = entry.version;
            }
        }

        epoch_ = snapshot.epoch;

        // 缓存全量 delta（用于转发给新节点）
        ConfigDelta full_delta;
        full_delta.from_epoch = 0;  // 全量
        full_delta.to_epoch = epoch_;
        full_delta.changes = snapshot.entries;
        full_delta.signature = snapshot.signature;  // 复用 snapshot 签名（简化：全量 delta 用 snapshot 签名）
        cached_delta_ = full_delta;

        save_history_locked(snapshot);

        LINOH_INFO("ConfigDistributor: apply_snapshot epoch=%llu entries=%zu",
                   static_cast<unsigned long long>(epoch_), entries_.size());
    }

    // 锁外通知订阅者
    for (const auto &[key, old_val, new_val] : changes) {
        notify_subscribers(key, old_val, new_val);
    }
    return true;
}

bool ConfigDistributor::apply_delta(const ConfigDelta &delta,
                                    const base::PublicKey &orchestrator_pubkey) {
    // 验证签名
    auto sig_data = delta.signing_data();
    if (!verify_signature_locked(sig_data, delta.signature, orchestrator_pubkey)) {
        LINOH_WARN("ConfigDistributor: apply_delta signature verification failed "
                   "(from=%llu, to=%llu)",
                   static_cast<unsigned long long>(delta.from_epoch),
                   static_cast<unsigned long long>(delta.to_epoch));
        return false;
    }

    std::vector<std::tuple<std::string, std::string, std::string>> changes;  // (key, old, new)

    {
        std::lock_guard<std::mutex> lk(mu_);

        // epoch 防回退
        if (delta.to_epoch <= epoch_) {
            LINOH_WARN("ConfigDistributor: apply_delta epoch rollback rejected "
                       "(current=%llu, delta_to=%llu)",
                       static_cast<unsigned long long>(epoch_),
                       static_cast<unsigned long long>(delta.to_epoch));
            return false;
        }

        // 应用变更（LWW 合并）
        for (const auto &entry : delta.changes) {
            auto it = entries_.find(entry.key);
            if (it != entries_.end() && it->second.version >= entry.version) {
                continue;  // 本地 version 更高，跳过（LWW）
            }
            std::string old_val = (it != entries_.end()) ? it->second.value : "";
            entries_[entry.key] = entry;
            changes.emplace_back(entry.key, old_val, entry.value);
            if (entry.version > version_counter_) {
                version_counter_ = entry.version;
            }
        }

        // 应用删除
        for (const auto &key : delta.deletions) {
            auto it = entries_.find(key);
            if (it != entries_.end()) {
                std::string old_val = it->second.value;
                entries_.erase(it);
                changes.emplace_back(key, old_val, "");
            }
        }

        epoch_ = delta.to_epoch;

        // 缓存 delta（用于转发给邻居）
        cached_delta_ = delta;

        // 保存历史快照
        ConfigSnapshot snapshot;
        snapshot.epoch = epoch_;
        snapshot.created_at = clock_();
        snapshot.origin = orchestrator_pubkey;
        snapshot.entries.reserve(entries_.size());
        for (const auto &[k, e] : entries_) {
            snapshot.entries.push_back(e);
        }
        save_history_locked(snapshot);

        LINOH_INFO("ConfigDistributor: apply_delta from=%llu to=%llu changes=%zu deletions=%zu",
                   static_cast<unsigned long long>(delta.from_epoch),
                   static_cast<unsigned long long>(delta.to_epoch),
                   delta.changes.size(), delta.deletions.size());
    }

    // 锁外通知订阅者
    for (const auto &[key, old_val, new_val] : changes) {
        notify_subscribers(key, old_val, new_val);
    }
    return true;
}

// ============================================================================
// gossip 传播
// ============================================================================

std::optional<ConfigDelta> ConfigDistributor::build_delta_for(
    const base::EndpointId &target) const {
    std::lock_guard<std::mutex> lk(mu_);

    if (!cached_delta_.has_value()) {
        return std::nullopt;  // 无缓存 delta
    }

    auto it = node_epochs_.find(target);
    std::uint64_t target_epoch = (it != node_epochs_.end()) ? it->second : 0;

    // 目标节点已是最新
    if (target_epoch >= cached_delta_->to_epoch) {
        return std::nullopt;
    }

    // 目标节点 epoch 比缓存的 delta 的 from_epoch 还旧
    // （delta 不覆盖其 epoch，需要全量同步，暂返回 nullopt 让 orchestrator 处理）
    if (target_epoch < cached_delta_->from_epoch && !cached_delta_->is_full()) {
        return std::nullopt;
    }

    return cached_delta_;
}

void ConfigDistributor::on_config_delta_received(
    const ConfigDelta &delta,
    const base::EndpointId &source,
    const base::PublicKey &orchestrator_pubkey) {
    // 更新 source 的 config_epoch
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = node_epochs_.find(source);
        if (it == node_epochs_.end() || it->second < delta.to_epoch) {
            node_epochs_[source] = delta.to_epoch;
        }
    }

    // 应用 delta
    apply_delta(delta, orchestrator_pubkey);
}

// ============================================================================
// 落后检测
// ============================================================================

std::vector<base::EndpointId> ConfigDistributor::lagging_nodes(
    std::uint64_t behind_epochs) const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<base::EndpointId> result;
    for (const auto &[node, node_epoch] : node_epochs_) {
        if (epoch_ > node_epoch && (epoch_ - node_epoch) >= behind_epochs) {
            result.push_back(node);
        }
    }
    return result;
}

void ConfigDistributor::update_node_config_epoch(const base::EndpointId &node,
                                                   std::uint64_t epoch) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = node_epochs_.find(node);
    if (it == node_epochs_.end() || it->second < epoch) {
        node_epochs_[node] = epoch;
    }
}

// ============================================================================
// 订阅热更新
// ============================================================================

std::size_t ConfigDistributor::subscribe(const std::string &key_prefix,
                                          ConfigChangeCallback cb) {
    std::lock_guard<std::mutex> lk(mu_);
    std::size_t handle = next_handle_.fetch_add(1, std::memory_order_relaxed);
    subscribers_[handle] = std::make_pair(key_prefix, std::move(cb));
    return handle;
}

void ConfigDistributor::unsubscribe(std::size_t handle) {
    std::lock_guard<std::mutex> lk(mu_);
    subscribers_.erase(handle);
}

void ConfigDistributor::notify_subscribers(const std::string &key,
                                            const std::string &old_val,
                                            const std::string &new_val) {
    // 收集匹配的回调（锁内收集，锁外调用防死锁）
    std::vector<ConfigChangeCallback> callbacks;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto &[handle, sub] : subscribers_) {
            const auto &prefix = sub.first;
            // 前缀匹配（空前缀匹配所有）
            if (prefix.empty() ||
                key.compare(0, prefix.size(), prefix) == 0) {
                callbacks.push_back(sub.second);
            }
        }
    }
    for (const auto &cb : callbacks) {
        try {
            cb(key, old_val, new_val);
        } catch (const std::exception &e) {
            LINOH_ERROR("ConfigDistributor: subscriber callback exception: %s", e.what());
        } catch (...) {
            LINOH_ERROR("ConfigDistributor: subscriber callback unknown exception");
        }
    }
}

// ============================================================================
// 回滚
// ============================================================================

bool ConfigDistributor::rollback_to(std::uint64_t target_epoch,
                                     const base::SecretKey &signing_key) {
    // 变更收集：(key, old_value, new_value)
    std::vector<std::tuple<std::string, std::string, std::string>> changes;
    bool success = false;

    {
        std::lock_guard<std::mutex> lk(mu_);

        // 查找历史快照
        auto it = std::find_if(history_.begin(), history_.end(),
                               [target_epoch](const ConfigSnapshot &s) {
                                   return s.epoch == target_epoch;
                               });
        if (it == history_.end()) {
            LINOH_WARN("ConfigDistributor: rollback target epoch %llu not found in history",
                       static_cast<unsigned long long>(target_epoch));
            return false;
        }

        // 回滚创建新的 epoch（不回退 epoch）
        ++epoch_;
        ++version_counter_;

        // 收集旧值
        std::unordered_map<std::string, std::string> old_values;
        for (const auto &entry : entries_) {
            old_values[entry.first] = entry.second.value;
        }

        // 替换为历史配置
        entries_.clear();
        for (auto entry : it->entries) {
            entry.version = ++version_counter_;  // 分配新 version
            entry.updated_at = clock_();
            std::string old_val = old_values.count(entry.key) ? old_values[entry.key] : "";
            if (old_val != entry.value) {
                changes.emplace_back(entry.key, old_val, entry.value);
            }
            entries_[entry.key] = entry;
        }

        // 保存回滚后的快照
        ConfigSnapshot snapshot;
        snapshot.epoch = epoch_;
        snapshot.created_at = clock_();
        snapshot.origin = signing_key.public_key();
        snapshot.entries.reserve(entries_.size());
        for (const auto &[k, e] : entries_) {
            snapshot.entries.push_back(e);
        }
        auto sig_data = snapshot.signing_data();
        auto sig = signing_key.sign(sig_data);
        std::memcpy(snapshot.signature.data(), sig.data(), 64);
        save_history_locked(snapshot);

        LINOH_INFO("ConfigDistributor: rollback_to epoch=%llu, new_epoch=%llu",
                   static_cast<unsigned long long>(target_epoch),
                   static_cast<unsigned long long>(epoch_));
        success = true;
    }

    // 锁外通知订阅者
    if (success) {
        for (const auto &[key, old_val, new_val] : changes) {
            notify_subscribers(key, old_val, new_val);
        }
    }
    return success;
}

std::size_t ConfigDistributor::history_size() const noexcept {
    return history_.size();
}

// ============================================================================
// 内部辅助
// ============================================================================

void ConfigDistributor::save_history_locked(const ConfigSnapshot &snapshot) {
    history_.push_back(snapshot);
    while (history_.size() > kMaxHistory) {
        history_.pop_front();
    }
}

bool ConfigDistributor::verify_signature_locked(
    const std::vector<std::uint8_t> &data,
    const std::array<std::uint8_t, 64> &sig,
    const base::PublicKey &pubkey) const {
    base::Signature signature{sig};  // 直接从 array 构造（Signature::data() 仅返回 const 指针）
    return signature.verify(data, pubkey);
}

}  // namespace linoh
