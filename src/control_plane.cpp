// control_plane.cpp — 轻量内置控制面实现（v2.0 Phase 1 交付物 7）
//
// 实现 NodeRegistry / HeartbeatAggregator / GossipDiscovery / ControlPlane

#include "linoh/control_plane.hpp"
#include "linoh/config_distributor.hpp"  // v2.1: ConfigDistributor
#include "linoh/address_lookup/lookup.hpp"  // V3-B: AddressLookup 完整定义（resolve_cross_domain_addr）
#include "linoh/event_bus.hpp"  // V3.4: EventBus/Subscriber/SubscriberConfig 完整定义

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <random>
#include <thread>

namespace linoh {

// ============================================================================
// NodeRegistry 实现
// ============================================================================

NodeRegistry::NodeRegistry(ClockFunc clock)
    : clock_(clock ? std::move(clock) : ClockFunc([]() { return std::chrono::system_clock::now(); })) {}

bool NodeRegistry::upsert(const NodeProfile &profile, NodeState state) {
    std::lock_guard<std::mutex> lk(mu_);
    auto now = clock_();
    auto it = entries_.find(profile.endpoint_id);
    if (it == entries_.end()) {
        NodeRegistryEntry entry;
        entry.profile = profile;
        entry.state = state;
        entry.last_seen = now;
        entry.registered_at = now;
        entries_.emplace(profile.endpoint_id, std::move(entry));
        return true;  // 新注册
    }
    // 更新
    it->second.profile = profile;
    it->second.state = state;
    it->second.last_seen = now;
    return false;
}

bool NodeRegistry::touch(const base::EndpointId &id) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = entries_.find(id);
    if (it == entries_.end()) return false;
    it->second.last_seen = clock_();
    if (it->second.state == NodeState::Offline) {
        it->second.state = NodeState::Online;  // 恢复
    }
    return true;
}

bool NodeRegistry::erase(const base::EndpointId &id) {
    std::lock_guard<std::mutex> lk(mu_);
    return entries_.erase(id) > 0;
}

std::optional<NodeRegistryEntry> NodeRegistry::get(const base::EndpointId &id) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = entries_.find(id);
    if (it == entries_.end()) return std::nullopt;
    return it->second;
}

std::vector<NodeRegistryEntry> NodeRegistry::snapshot() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<NodeRegistryEntry> result;
    result.reserve(entries_.size());
    for (const auto &[_, entry] : entries_) {
        result.push_back(entry);
    }
    return result;
}

std::size_t NodeRegistry::size() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return entries_.size();
}

std::vector<NodeRegistryEntry> NodeRegistry::get_by_region(GeoRegion region) const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<NodeRegistryEntry> result;
    for (const auto &[_, entry] : entries_) {
        if (entry.profile.geo.region == region) {
            result.push_back(entry);
        }
    }
    return result;
}

std::vector<base::EndpointId> NodeRegistry::mark_stale(std::chrono::seconds timeout) {
    std::lock_guard<std::mutex> lk(mu_);
    auto now = clock_();
    std::vector<base::EndpointId> stale_ids;
    for (auto &[id, entry] : entries_) {
        if (entry.state == NodeState::Offline) continue;  // 已离线跳过
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - entry.last_seen);
        if (elapsed > timeout) {
            entry.state = NodeState::Offline;
            stale_ids.push_back(id);
        }
    }
    return stale_ids;
}

std::optional<base::EndpointId> NodeRegistry::elect_region_representative(
    GeoRegion region) const {
    std::lock_guard<std::mutex> lk(mu_);
    const NodeRegistryEntry *best = nullptr;
    float best_score = -1.0f;
    for (const auto &[_, entry] : entries_) {
        if (entry.profile.geo.region != region) continue;
        if (entry.state != NodeState::Online) continue;
        float s = entry.profile.stability.score;
        if (s > best_score) {
            best_score = s;
            best = &entry;
        }
    }
    if (best) return best->profile.endpoint_id;
    return std::nullopt;
}

void NodeRegistry::add_neighbor(const base::EndpointId &a, const base::EndpointId &b) {
    std::lock_guard<std::mutex> lk(mu_);
    auto add_one = [&](const base::EndpointId &self, const base::EndpointId &peer) {
        auto it = entries_.find(self);
        if (it == entries_.end()) return;
        auto &neighbors = it->second.neighbors;
        // 去重
        if (std::find(neighbors.begin(), neighbors.end(), peer) == neighbors.end()) {
            neighbors.push_back(peer);
        }
    };
    add_one(a, b);
    add_one(b, a);
}

std::vector<base::EndpointId> NodeRegistry::get_neighbors(
    const base::EndpointId &id) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = entries_.find(id);
    if (it == entries_.end()) return {};
    return it->second.neighbors;
}

// ============================================================================
// HeartbeatAggregator 实现
// ============================================================================

HeartbeatAggregator::HeartbeatAggregator(NodeRegistry &registry,
                                         ControlPlaneConfig cfg,
                                         ClockFunc clock)
    : registry_(registry),
      config_(std::move(cfg)),
      clock_(clock ? std::move(clock) : ClockFunc([]() { return std::chrono::system_clock::now(); })) {}

void HeartbeatAggregator::on_heartbeat_received(const HeartbeatPayloadV2 &payload) {
    hb_received_.fetch_add(1, std::memory_order_relaxed);

    // 刷新发送者的 last_seen
    registry_.touch(payload.sender_id);

    // 处理 gossip piggyback：注册未知节点（仅记录 EndpointId，无完整 Profile）
    // 上层收到新节点事件后可通过其他途径获取完整 Profile
    for (const auto &node_id : payload.known_nodes) {
        auto existing = registry_.get(node_id);
        if (!existing.has_value()) {
            // 新节点发现，插入占位条目（state=Unknown，等待完整 Profile 更新）
            NodeProfile placeholder;
            placeholder.endpoint_id = node_id;
            placeholder.geo.region = payload.region;  // 暂用发送者区域
            registry_.upsert(placeholder, NodeState::Unknown);
        }
    }
}

HeartbeatPayloadV2 HeartbeatAggregator::build_heartbeat(
    const base::EndpointId &self_id,
    const NodeProfile &self_profile) const {
    HeartbeatPayloadV2 hb;
    hb.sender_id = self_id;
    hb.timestamp = clock_();
    hb.region = self_profile.geo.region;
    hb.stability_score = self_profile.stability.score;

    // piggyback：从注册表采样已知节点
    auto all = registry_.snapshot();
    std::vector<base::EndpointId> candidates;
    candidates.reserve(all.size());
    for (const auto &entry : all) {
        if (entry.profile.endpoint_id == self_id) continue;  // 排除自己
        candidates.push_back(entry.profile.endpoint_id);
    }
    // 随机采样（不超过 max_known_nodes）
    if (candidates.size() > config_.max_known_nodes) {
        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(candidates.begin(), candidates.end(), g);
        candidates.resize(config_.max_known_nodes);
    }
    hb.known_nodes = std::move(candidates);
    return hb;
}

std::vector<base::EndpointId> HeartbeatAggregator::select_gossip_targets(
    const base::EndpointId &self_id) const {
    auto neighbors = registry_.get_neighbors(self_id);
    if (neighbors.size() <= config_.gossip_fanout) {
        return neighbors;
    }
    // 随机选择 fanout 个
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(neighbors.begin(), neighbors.end(), g);
    neighbors.resize(config_.gossip_fanout);
    return neighbors;
}

std::vector<NodeEvent> HeartbeatAggregator::check_stale() {
    std::vector<NodeEvent> events;
    auto stale_ids = registry_.mark_stale(config_.stale_timeout);
    events.reserve(stale_ids.size());
    auto now = clock_();
    for (const auto &id : stale_ids) {
        NodeEvent ev;
        ev.type = NodeEventType::NodeStale;
        ev.endpoint_id = id;
        ev.timestamp = now;
        ev.detail = "heartbeat_timeout";
        events.push_back(std::move(ev));
    }
    return events;
}

std::size_t HeartbeatAggregator::heartbeats_received() const noexcept {
    return hb_received_.load(std::memory_order_relaxed);
}

// ============================================================================
// GossipDiscovery 实现
// ============================================================================

GossipDiscovery::GossipDiscovery(NodeRegistry &registry,
                                 ControlPlaneConfig cfg,
                                 ClockFunc clock)
    : registry_(registry),
      config_(std::move(cfg)),
      clock_(clock ? std::move(clock) : ClockFunc([]() { return std::chrono::system_clock::now(); })) {}

void GossipDiscovery::on_gossip_nodes(const std::vector<base::EndpointId> &known_nodes,
                                       const base::EndpointId &source) {
    gossip_rounds_.fetch_add(1, std::memory_order_relaxed);

    // 将 source 添加为邻居（如果尚未存在）
    auto src_entry = registry_.get(source);
    if (src_entry.has_value()) {
        // 遍历 known_nodes，将未注册的节点添加占位条目
        for (const auto &node_id : known_nodes) {
            auto existing = registry_.get(node_id);
            if (!existing.has_value()) {
                NodeProfile placeholder;
                placeholder.endpoint_id = node_id;
                registry_.upsert(placeholder, NodeState::Unknown);
            }
        }
    }
}

std::vector<base::EndpointId> GossipDiscovery::discover(std::size_t max_count) const {
    auto all = registry_.snapshot();
    // 过滤 Online 节点，按 overall_score 降序
    std::vector<const NodeRegistryEntry *> online;
    online.reserve(all.size());
    for (const auto &entry : all) {
        if (entry.state == NodeState::Online) {
            online.push_back(&entry);
        }
    }
    std::sort(online.begin(), online.end(),
              [](const NodeRegistryEntry *a, const NodeRegistryEntry *b) {
                  return a->profile.overall_score() > b->profile.overall_score();
              });
    std::vector<base::EndpointId> result;
    result.reserve(std::min(max_count, online.size()));
    for (std::size_t i = 0; i < online.size() && i < max_count; ++i) {
        result.push_back(online[i]->profile.endpoint_id);
    }
    return result;
}

std::vector<base::EndpointId> GossipDiscovery::build_piggyback(
    const base::EndpointId &self_id) const {
    auto all = registry_.snapshot();
    std::vector<base::EndpointId> candidates;
    candidates.reserve(all.size());
    for (const auto &entry : all) {
        if (entry.profile.endpoint_id == self_id) continue;
        candidates.push_back(entry.profile.endpoint_id);
    }
    if (candidates.size() <= config_.max_known_nodes) {
        return candidates;
    }
    // 随机采样
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(candidates.begin(), candidates.end(), g);
    candidates.resize(config_.max_known_nodes);
    return candidates;
}

std::size_t GossipDiscovery::gossip_rounds() const noexcept {
    return gossip_rounds_.load(std::memory_order_relaxed);
}

// ============================================================================
// ControlPlane 实现
// ============================================================================

ControlPlane::ControlPlane()
    : config_(),
      clock_([]() { return std::chrono::system_clock::now(); }),
      registry_(clock_),
      last_heartbeat_(),
      last_aggregate_(),
      last_orchestrator_sync_(),
      last_config_push_(),
      last_cross_domain_aggregate_(),
      last_cross_domain_stale_check_() {
    aggregator_ = std::make_unique<HeartbeatAggregator>(registry_, config_, clock_);
    discovery_ = std::make_unique<GossipDiscovery>(registry_, config_, clock_);
    distributor_ = std::make_unique<ConfigDistributor>(registry_, config_, clock_);
    cross_domain_agg_ = std::make_unique<CrossDomainAggregator>(registry_, config_, clock_);
}

ControlPlane::~ControlPlane() {
    // V3.4: 停止所有 EventBus 订阅者（唤醒阻塞的 poll / Block deliver）
    if (event_bus_) {
        event_bus_->stop_all();
    }
}

ControlPlane::ControlPlane(ControlPlaneConfig cfg, ClockFunc clock)
    : config_(std::move(cfg)),
      clock_(clock ? std::move(clock) : ClockFunc([]() { return std::chrono::system_clock::now(); })),
      registry_(clock_),
      last_heartbeat_(),
      last_aggregate_(),
      last_orchestrator_sync_(),
      last_config_push_(),
      last_cross_domain_aggregate_(),
      last_cross_domain_stale_check_() {
    aggregator_ = std::make_unique<HeartbeatAggregator>(registry_, config_, clock_);
    discovery_ = std::make_unique<GossipDiscovery>(registry_, config_, clock_);
    distributor_ = std::make_unique<ConfigDistributor>(registry_, config_, clock_);
    cross_domain_agg_ = std::make_unique<CrossDomainAggregator>(registry_, config_, clock_);
}

void ControlPlane::start(const base::EndpointId &self_id,
                          const NodeProfile &self_profile) {
    std::lock_guard<std::mutex> lk(mu_);
    if (running_.load()) return;
    self_id_ = self_id;
    self_profile_ = self_profile;
    auto now = clock_();
    last_heartbeat_ = now;
    last_aggregate_ = now;
    last_orchestrator_sync_ = now;
    last_config_push_ = now;
    last_cross_domain_aggregate_ = now;       // V3-A
    last_cross_domain_stale_check_ = now;     // V3-A
    running_.store(true);

    // 注册自己
    registry_.upsert(self_profile_, NodeState::Online);
    // V3-A: 跨域启用时设置本节点 domain_id（供 elect_cross_domain_rep 选举）
    if (config_.cross_domain_enabled && config_.domain_id != 0) {
        registry_.set_domain(self_id_, config_.domain_id);
    }
    emit_event(NodeEventType::NodeJoined, self_id_, "self_registered");
}

void ControlPlane::stop() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!running_.load()) return;
    running_.store(false);
    emit_event(NodeEventType::NodeLeft, self_id_, "self_stopped");
}

void ControlPlane::register_node(const NodeProfile &profile) {
    std::lock_guard<std::mutex> lk(mu_);
    bool is_new = registry_.upsert(profile, NodeState::Online);
    if (is_new) {
        emit_event(NodeEventType::NodeJoined, profile.endpoint_id, "registered");
    } else {
        emit_event(NodeEventType::NodeUpdated, profile.endpoint_id, "profile_updated");
    }
}

std::vector<base::EndpointId> ControlPlane::discover_nodes(std::size_t max_count) {
    if (!config_.enabled) return {};
    return discovery_->discover(max_count);
}

void ControlPlane::tick_once() {
    if (!running_.load() || !config_.enabled) return;

    std::unique_lock<std::mutex> lk(mu_);
    auto now = clock_();

    // V3-A 修复：刷新本节点 last_seen（本节点 running=true 时始终视为在线，
    // 避免 mark_stale 误将本节点标记为 Offline 导致跨域代表选举失败）
    registry_.touch(self_id_);

    // 心跳发送（锁内收集，锁外发送）
    std::vector<std::pair<base::EndpointId, HeartbeatPayloadV2>> pending_heartbeats;
    auto hb_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_heartbeat_);
    if (hb_elapsed >= config_.heartbeat_interval) {
        auto hb = aggregator_->build_heartbeat(self_id_, self_profile_);
        // v2.1: 心跳携带当前 config_epoch（用于落后检测）
        hb.config_epoch = distributor_->current_epoch();
        auto targets = aggregator_->select_gossip_targets(self_id_);
        for (const auto &target : targets) {
            pending_heartbeats.emplace_back(target, hb);
        }
        last_heartbeat_ = now;
    }

    // 超时检测（V3.5 P5-C: 走 emit_event 保证 EventBus 订阅者也能收到 NodeStale）
    auto stale_events = aggregator_->check_stale();
    for (const auto &ev : stale_events) {
        emit_event(ev.type, ev.endpoint_id, ev.detail);
    }

    // 区域代表聚合（简化：仅记录时间戳，实际上报留待 orchestrator 集成）
    auto agg_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_aggregate_);
    if (agg_elapsed >= config_.aggregate_interval) {
        last_aggregate_ = now;
    }

    // v2.1: 配置同步（向邻居传播缓存的 ConfigDelta）
    std::vector<std::pair<base::EndpointId, ConfigDelta>> pending_config_pushes;
    auto config_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_config_push_);
    if (config_elapsed >= config_.heartbeat_interval && send_config_cb_) {
        auto neighbors = registry_.get_neighbors(self_id_);
        for (const auto &neighbor : neighbors) {
            auto delta_opt = distributor_->build_delta_for(neighbor);
            if (delta_opt.has_value()) {
                pending_config_pushes.emplace_back(neighbor, std::move(delta_opt.value()));
            }
        }
        last_config_push_ = now;
    }

    // 锁外发送心跳和配置（避免回调中再次获取 mu_ 导致死锁）
    lk.unlock();

    if (send_cb_) {
        for (auto &[target, hb] : pending_heartbeats) {
            try { send_cb_(target, hb); } catch (...) {}
        }
    }

    if (send_config_cb_) {
        for (auto &[target, delta] : pending_config_pushes) {
            try { send_config_cb_(target, delta); } catch (...) {}
        }
    }

    // V3-A: 跨域 tick（跨域未启用时 no-op）
    tick_cross_domain_();
}

void ControlPlane::subscribe_node_events(NodeEventCallback cb) {
    // V3.4: 旧接口保持同步语义（向后兼容）
    // emit_event 会同时调用 event_cb_（同步）和 publish 到 EventBus（异步，若已初始化）
    // 新 subscribe_events 走 EventBus 异步多订阅者路径，两者独立并存
    std::lock_guard<std::mutex> lk(mu_);
    event_cb_ = std::move(cb);
}

// ============================================================================
// V3.4: EventBus 集成实现
// ============================================================================

EventBus &ControlPlane::event_bus() {
    std::lock_guard<std::mutex> lk(event_bus_mtx_);
    if (!event_bus_) {
        event_bus_ = std::make_unique<EventBus>(clock_);
    }
    return *event_bus_;
}

std::shared_ptr<Subscriber> ControlPlane::subscribe_events(const SubscriberConfig &config) {
    return event_bus().subscribe(config);
}

std::shared_ptr<Subscriber> ControlPlane::subscribe_events() {
    return event_bus().subscribe();
}

std::vector<NodeRegistryEntry> ControlPlane::sync_with_orchestrator() const {
    // stub：返回本地注册表快照
    // 实际 orchestrator HTTP 同步留待后续交付
    return registry_.snapshot();
}

void ControlPlane::on_heartbeat_received(const HeartbeatPayloadV2 &payload) {
    if (!config_.enabled) return;

    aggregator_->on_heartbeat_received(payload);

    // 处理 gossip 传播
    discovery_->on_gossip_nodes(payload.known_nodes, payload.sender_id);

    // v2.1: 更新节点的 config_epoch（用于落后检测）
    distributor_->update_node_config_epoch(payload.sender_id, payload.config_epoch);

    // 如果发送者是首次发现，触发 NodeJoined 事件
    auto entry = registry_.get(payload.sender_id);
    if (entry.has_value() && entry->state == NodeState::Unknown) {
        // 从 Unknown 恢复为 Online
        registry_.touch(payload.sender_id);
        std::lock_guard<std::mutex> lk(mu_);
        emit_event(NodeEventType::NodeJoined, payload.sender_id, "discovered_via_gossip");
    }
}

void ControlPlane::set_send_callback(SendHeartbeatCallback cb) {
    std::lock_guard<std::mutex> lk(mu_);
    send_cb_ = std::move(cb);
}

void ControlPlane::emit_event(NodeEventType type,
                               const base::EndpointId &id,
                               const std::string &detail) {
    // 调用方已持 mu_
    NodeEvent ev;
    ev.type = type;
    ev.endpoint_id = id;
    ev.timestamp = clock_();
    ev.detail = detail;

    // V3.4 路径 1：同步调用旧 callback（v3.3 行为，向后兼容）
    // subscribe_node_events 设置的 callback 在此同步收到事件（无异步延迟）
    if (event_cb_) {
        event_cb_(ev);
    }

    // V3.4 路径 2：异步 publish 到 EventBus（新 subscribe_events 订阅者）
    // 不在 mu_ 持有期间持 event_bus_mtx_ 并 publish（避免 mu_→event_bus_mtx_→subscriber 锁嵌套）：
    // 先在 event_bus_mtx_ 下取裸指针，释放后再 publish
    // （event_bus_ 一旦创建不销毁，裸指针在 ControlPlane 生命周期内安全）
    EventBus *bus = nullptr;
    {
        std::lock_guard<std::mutex> lk(event_bus_mtx_);
        bus = event_bus_.get();
    }
    if (bus) {
        bus->publish(ev);  // publish 自身线程安全，fan-out 到所有 Subscriber
    }
}

// ============================================================================
// v2.1 Phase 2: 配置分发接口实现
// ============================================================================

ConfigDistributor &ControlPlane::distributor() {
    return *distributor_;
}

const ConfigDistributor &ControlPlane::distributor() const {
    return *distributor_;
}

void ControlPlane::set_orchestrator_pubkey(base::PublicKey pubkey) {
    std::lock_guard<std::mutex> lk(mu_);
    orchestrator_pubkey_ = std::move(pubkey);
}

void ControlPlane::set_send_config_callback(SendConfigCallback cb) {
    std::lock_guard<std::mutex> lk(mu_);
    send_config_cb_ = std::move(cb);
}

void ControlPlane::on_config_delta_received(const ConfigDelta &delta,
                                              const base::EndpointId &source) {
    // 应用 delta（验证签名 + LWW 合并 + 触发热更新）
    // 注意：orchestrator_pubkey_ 需要提前通过 set_orchestrator_pubkey 设置
    distributor_->on_config_delta_received(delta, source, orchestrator_pubkey_);
}

// ============================================================================
// V3-A: 跨域控制面实现（M1 桩，M2 阶段补全具体逻辑）
// ============================================================================
//
// M1 阶段：所有方法返回安全默认值，确保链接通过且行为向后兼容。
//   - 跨域未启用（cross_domain_enabled=false 或 domain_id=0）时全部 no-op
//   - 跨域启用但未实现时返回空/0/false，不触发任何跨域行为
// M2 阶段：补全 build_digest/on_digest_received/upsert_cross_domain_digests 等

// ----------------------------------------------------------------------------
// CrossDomainNodeDigest / CrossDomainDigestPayload
// ----------------------------------------------------------------------------

std::size_t CrossDomainNodeDigest::serialize(std::uint8_t *out, std::size_t cap) const {
    // M2: 42 字节固定布局序列化（小端序）
    //   domain_id(4) + endpoint_id(32) + overall_score(4) + region(1) + state(1)
    if (out == nullptr || cap < kSerializedSize) return 0;
    std::memcpy(out, &domain_id, 4);                      // domain_id (4 bytes, LE)
    std::memcpy(out + 4, endpoint_id.data(), 32);         // endpoint_id (32 bytes)
    std::memcpy(out + 36, &overall_score, 4);             // overall_score (4 bytes, LE)
    out[40] = static_cast<std::uint8_t>(region);          // region (1 byte)
    out[41] = static_cast<std::uint8_t>(state);           // state (1 byte)
    return kSerializedSize;
}

std::size_t CrossDomainNodeDigest::deserialize(const std::uint8_t *in, std::size_t len,
                                                CrossDomainNodeDigest &out) {
    // M2: 42 字节固定布局反序列化
    if (in == nullptr || len < kSerializedSize) return 0;
    std::memcpy(&out.domain_id, in, 4);                       // domain_id
    out.endpoint_id = base::PublicKey::from_bytes(
        std::span<const uint8_t>(in + 4, 32));                // endpoint_id
    std::memcpy(&out.overall_score, in + 36, 4);              // overall_score
    out.region = static_cast<GeoRegion>(in[40]);               // region
    out.state = static_cast<NodeState>(in[41]);                // state
    return kSerializedSize;
}

std::string CrossDomainNodeDigest::brief() const {
    // M1 桩：返回基本信息
    return "CrossDomainNodeDigest{domain=" + std::to_string(domain_id) +
           ", score=" + std::to_string(overall_score) + "}";
}

bool CrossDomainDigestPayload::within_limit(std::size_t max_digest_nodes) const noexcept {
    return nodes.size() <= max_digest_nodes;
}

std::string CrossDomainDigestPayload::brief() const {
    return "CrossDomainDigestPayload{sender_domain=" + std::to_string(sender_domain_id) +
           ", ttl=" + std::to_string(ttl) +
           ", nodes=" + std::to_string(nodes.size()) + "}";
}

// ----------------------------------------------------------------------------
// NodeRegistry 跨域接口（M1 桩）
// ----------------------------------------------------------------------------

std::size_t NodeRegistry::upsert_cross_domain_digests(
    const std::vector<CrossDomainNodeDigest> &digests,
    std::uint32_t self_domain) {
    // M2: batch upsert + is_cross_domain 标记 + 新发现计数
    std::lock_guard<std::mutex> lk(mu_);
    std::size_t new_count = 0;
    auto now = clock_();
    for (const auto &d : digests) {
        auto it = entries_.find(d.endpoint_id);
        if (it == entries_.end()) {
            // 新跨域节点
            NodeRegistryEntry entry;
            entry.profile.endpoint_id = d.endpoint_id;
            entry.profile.geo.region = d.region;
            entry.state = d.state;
            entry.last_seen = now;
            entry.registered_at = now;
            entry.domain_id = d.domain_id;
            entry.is_cross_domain = (d.domain_id != self_domain);
            entry.digest_received_at = now;
            entry.cached_overall_score = d.overall_score;
            entries_.emplace(d.endpoint_id, std::move(entry));
            ++new_count;
        } else {
            // 已存在节点，更新跨域摘要
            auto &entry = it->second;
            entry.state = d.state;
            entry.domain_id = d.domain_id;
            entry.is_cross_domain = (d.domain_id != self_domain);
            entry.digest_received_at = now;
            entry.cached_overall_score = d.overall_score;
            entry.profile.geo.region = d.region;  // 同步区域信息
        }
    }
    return new_count;
}

std::vector<NodeRegistryEntry> NodeRegistry::get_by_domain(std::uint32_t domain_id) const {
    // M1 桩：M2 实现按 domain 筛选
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<NodeRegistryEntry> result;
    for (const auto &kv : entries_) {
        if (kv.second.domain_id == domain_id) {
            result.push_back(kv.second);
        }
    }
    return result;
}

std::vector<NodeRegistryEntry> NodeRegistry::get_cross_domain_nodes() const {
    // M2: 按 is_cross_domain 筛选 + sort_score 降序排序
    // 跨域节点用 cached_overall_score（通过 sort_score() 获取）
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<NodeRegistryEntry> result;
    for (const auto &kv : entries_) {
        if (kv.second.is_cross_domain) {
            result.push_back(kv.second);
        }
    }
    std::sort(result.begin(), result.end(),
              [](const NodeRegistryEntry &a, const NodeRegistryEntry &b) {
                  return a.sort_score() > b.sort_score();
              });
    return result;
}

std::optional<base::EndpointId> NodeRegistry::elect_cross_domain_rep(
    std::uint32_t domain_id) const {
    // M2: sort_score 最高者选举 + 平局字典序最小（确定性）
    // 跨域节点用 cached_overall_score（通过 sort_score() 获取）
    std::lock_guard<std::mutex> lk(mu_);
    std::optional<base::EndpointId> best;
    float best_score = -1.0f;
    for (const auto &kv : entries_) {
        if (kv.second.domain_id != domain_id) continue;
        if (kv.second.state == NodeState::Offline) continue;
        float s = kv.second.sort_score();
        if (s > best_score ||
            (s == best_score && best.has_value() && kv.first < *best)) {
            best_score = s;
            best = kv.first;
        }
    }
    return best;
}

void NodeRegistry::set_cross_domain_rep(const base::EndpointId &id, bool is_rep) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = entries_.find(id);
    if (it != entries_.end()) {
        it->second.is_cross_domain_rep = is_rep;
    }
}

void NodeRegistry::set_domain(const base::EndpointId &id, std::uint32_t domain_id) {
    // V3-A: 设置节点所属域（本节点启动时由 ControlPlane 调用）
    std::lock_guard<std::mutex> lk(mu_);
    auto it = entries_.find(id);
    if (it != entries_.end()) {
        it->second.domain_id = domain_id;
        it->second.is_cross_domain = false;  // 本节点不是跨域节点
    }
}

std::vector<base::EndpointId> NodeRegistry::mark_cross_domain_stale(
    std::chrono::seconds timeout) {
    // M1 桩：M2 实现跨域节点超时清理（仅清理 is_cross_domain=true 的节点）
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<base::EndpointId> stale;
    auto now = clock_();
    for (auto it = entries_.begin(); it != entries_.end(); ) {
        if (it->second.is_cross_domain) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.digest_received_at);
            if (age > timeout) {
                stale.push_back(it->first);
                it = entries_.erase(it);
                continue;
            }
        }
        ++it;
    }
    return stale;
}

// ----------------------------------------------------------------------------
// CrossDomainAggregator（M1 桩）
// ----------------------------------------------------------------------------

CrossDomainAggregator::CrossDomainAggregator(NodeRegistry &registry,
                                              ControlPlaneConfig cfg,
                                              ClockFunc clock)
    : registry_(registry), config_(std::move(cfg)), clock_(std::move(clock)) {}

CrossDomainDigestPayload CrossDomainAggregator::build_digest(
    const base::EndpointId &self_id,
    std::uint32_t self_domain) const {
    // M2: 从 registry 提取本域在线节点 + 按 sort_score 降序取前 max_digest_nodes
    // 本域节点判定：is_cross_domain=false（通过 upsert 注册的节点默认此标志）
    CrossDomainDigestPayload payload;
    payload.sender_domain_id = self_domain;
    payload.ttl = config_.cross_domain_ttl;
    payload.sender_endpoint_id = self_id;

    auto all = registry_.snapshot();
    std::vector<NodeRegistryEntry> domain_nodes;
    for (const auto &entry : all) {
        if (!entry.is_cross_domain && entry.state != NodeState::Offline) {
            domain_nodes.push_back(entry);
        }
    }
    std::sort(domain_nodes.begin(), domain_nodes.end(),
              [](const NodeRegistryEntry &a, const NodeRegistryEntry &b) {
                  return a.sort_score() > b.sort_score();
              });
    std::size_t limit = (std::min)(domain_nodes.size(), config_.max_digest_nodes);
    payload.nodes.reserve(limit);
    for (std::size_t i = 0; i < limit; ++i) {
        const auto &entry = domain_nodes[i];
        CrossDomainNodeDigest d;
        d.domain_id = self_domain;
        d.endpoint_id = entry.profile.endpoint_id;
        d.overall_score = entry.sort_score();
        d.region = entry.profile.geo.region;
        d.state = entry.state;
        payload.nodes.push_back(d);
    }
    return payload;
}

std::size_t CrossDomainAggregator::on_digest_received(
    const CrossDomainDigestPayload &payload,
    std::uint32_t self_domain) {
    // M2: 同域摘要过滤 + upsert + 新发现计数
    digests_received_.fetch_add(1, std::memory_order_relaxed);
    if (payload.sender_domain_id == self_domain) {
        return 0;  // 同域不处理（避免环路）
    }
    return registry_.upsert_cross_domain_digests(payload.nodes, self_domain);
}

bool CrossDomainAggregator::should_forward(const CrossDomainDigestPayload &payload) const noexcept {
    return payload.ttl > 1;
}

std::vector<base::EndpointId> CrossDomainAggregator::select_forward_targets(
    const CrossDomainDigestPayload &payload,
    const std::vector<base::EndpointId> &peer_reps) const {
    // M2: 排除来源域代表（通过 registry 查询 rep 的 domain_id）
    // linoh 不决策与哪些域通信，仅从 peer_reps 中排除来源域
    std::vector<base::EndpointId> targets;
    for (const auto &rep : peer_reps) {
        auto entry = registry_.get(rep);
        if (entry.has_value() && entry->domain_id == payload.sender_domain_id) {
            continue;  // 来源域代表，排除
        }
        targets.push_back(rep);
    }
    digests_forwarded_.fetch_add(targets.size(), std::memory_order_relaxed);
    return targets;
}

std::vector<NodeEvent> CrossDomainAggregator::check_cross_domain_stale() {
    // M1 桩：M2 实现 mark_cross_domain_stale + 生成 NodeStale 事件
    std::vector<NodeEvent> events;
    auto stale_ids = registry_.mark_cross_domain_stale(config_.cross_domain_stale_timeout);
    for (const auto &id : stale_ids) {
        NodeEvent ev{};
        ev.type = NodeEventType::NodeStale;
        ev.endpoint_id = id;
        ev.timestamp = clock_();
        ev.detail = "cross_domain_stale";
        events.push_back(ev);
    }
    return events;
}

std::size_t CrossDomainAggregator::digests_received() const noexcept {
    return digests_received_.load(std::memory_order_relaxed);
}

std::size_t CrossDomainAggregator::digests_forwarded() const noexcept {
    return digests_forwarded_.load(std::memory_order_relaxed);
}

// ----------------------------------------------------------------------------
// ControlPlane 跨域接口（M1 桩）
// ----------------------------------------------------------------------------

void ControlPlane::set_send_digest_callback(SendDigestCallback cb) {
    std::lock_guard<std::mutex> lk(mu_);
    send_digest_cb_ = std::move(cb);
}

std::size_t ControlPlane::on_digest_received(const CrossDomainDigestPayload &payload) {
    // V3.5 P5-C: 跨域摘要接收 → upsert + emit NodeJoined/NodeUpdated 事件到 EventBus
    if (!config_.cross_domain_enabled || config_.domain_id == 0) {
        return 0;
    }
    // 同域摘要不处理（避免环路），提前返回避免无谓查询
    if (payload.sender_domain_id == config_.domain_id) {
        return 0;
    }

    std::lock_guard<std::mutex> lk(mu_);

    // 记录 upsert 前节点存在状态，用于区分 NodeJoined / NodeUpdated
    // 持 mu_ 期间调用 registry_.get（锁顺序 mu_ → registry_.mu_，无死锁）
    std::unordered_set<base::EndpointId> existing;
    for (const auto &d : payload.nodes) {
        if (registry_.get(d.endpoint_id).has_value()) {
            existing.insert(d.endpoint_id);
        }
    }

    std::size_t new_count = cross_domain_agg_->on_digest_received(payload, config_.domain_id);

    // V3.5 P5-C: emit 事件到 EventBus（新节点 NodeJoined / 已存在 NodeUpdated）
    // emit_event 同步调用旧 callback + 异步 publish 到 EventBus，保证两条路径都收到
    for (const auto &d : payload.nodes) {
        if (existing.count(d.endpoint_id) > 0) {
            emit_event(NodeEventType::NodeUpdated, d.endpoint_id,
                       "cross_domain_digest_update");
        } else {
            emit_event(NodeEventType::NodeJoined, d.endpoint_id,
                       "cross_domain_digest_discovered");
        }
    }

    return new_count;
}

std::vector<NodeRegistryEntry> ControlPlane::get_cross_domain_view() const {
    // M1：纯数据查询，linoh 不参与调度决策
    if (!config_.cross_domain_enabled || config_.domain_id == 0) {
        return {};
    }
    return registry_.get_cross_domain_nodes();
}

bool ControlPlane::is_cross_domain_rep() const noexcept {
    // M3: 返回由 tick_cross_domain_ 定期选举更新的标志
    // 跨域未启用时始终返回 false（向后兼容）
    if (!config_.cross_domain_enabled || config_.domain_id == 0) {
        return false;
    }
    return is_self_cross_domain_rep_.load(std::memory_order_acquire);
}

CrossDomainAggregator &ControlPlane::cross_domain_aggregator() {
    return *cross_domain_agg_;
}

const CrossDomainAggregator &ControlPlane::cross_domain_aggregator() const {
    return *cross_domain_agg_;
}

void ControlPlane::tick_cross_domain_() {
    // M3: 跨域 tick 逻辑（由 tick_once 在锁外调用，本方法内部自行加锁）
    if (!config_.cross_domain_enabled || config_.domain_id == 0) {
        return;
    }

    std::unique_lock<std::mutex> lk(mu_);
    auto now = clock_();

    // 计算各阶段是否到期
    auto agg_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_cross_domain_aggregate_);
    bool need_aggregate = (agg_elapsed >= config_.cross_domain_aggregate_interval);

    // V3.5 P5-C: 跨域 stale 检查间隔改为 cross_domain_stale_timeout（而非 aggregate_interval）
    // 避免 stale_timeout 短但检查间隔长（默认 30s）导致无法及时清理过期跨域节点
    auto stale_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_cross_domain_stale_check_);
    bool need_stale_check = (stale_elapsed >= config_.cross_domain_stale_timeout);

    // ----------------------------------------------------------------
    // 阶段 1：跨域代表选举（到期时执行）
    // ----------------------------------------------------------------
    if (need_aggregate) {
        auto rep_opt = registry_.elect_cross_domain_rep(config_.domain_id);
        bool was_rep = is_self_cross_domain_rep_.load(std::memory_order_acquire);
        bool is_rep = rep_opt.has_value() && *rep_opt == self_id_;
        is_self_cross_domain_rep_.store(is_rep, std::memory_order_release);

        // 同步标记到 registry（供 get_cross_domain_view 查询 is_cross_domain_rep 字段）
        registry_.set_cross_domain_rep(self_id_, is_rep);

        // 代表变更事件通知
        if (is_rep && !was_rep) {
            emit_event(NodeEventType::RegionRepChanged, self_id_,
                       "elected_as_cross_domain_rep");
        } else if (!is_rep && was_rep) {
            emit_event(NodeEventType::RegionRepChanged, self_id_,
                       "lost_cross_domain_rep");
        }
    }

    // ----------------------------------------------------------------
    // 阶段 2：跨域代表发送本域摘要（锁内构造，锁外发送）
    // ----------------------------------------------------------------
    CrossDomainDigestPayload digest_to_send;
    bool has_digest_to_send = false;
    if (need_aggregate && is_self_cross_domain_rep_.load(std::memory_order_acquire) &&
        send_digest_cb_ && !config_.peer_domain_reps.empty()) {
        digest_to_send = cross_domain_agg_->build_digest(self_id_, config_.domain_id);
        has_digest_to_send = true;
        last_cross_domain_aggregate_ = now;  // 仅在实际发送时更新时间戳
    } else if (need_aggregate) {
        // 非代表节点也更新时间戳，避免每 tick 都重算选举
        last_cross_domain_aggregate_ = now;
    }

    // ----------------------------------------------------------------
    // 阶段 3：跨域节点超时清理（所有节点都做）
    // V3.5 P5-C: 走 emit_event 保证 EventBus 订阅者收到 NodeStale
    // ----------------------------------------------------------------
    if (need_stale_check) {
        auto stale_events = cross_domain_agg_->check_cross_domain_stale();
        for (const auto &ev : stale_events) {
            emit_event(ev.type, ev.endpoint_id, ev.detail);
        }
        last_cross_domain_stale_check_ = now;
    }

    // ----------------------------------------------------------------
    // 锁外发送摘要（避免回调中再次获取 mu_ 导致死锁）
    // ----------------------------------------------------------------
    std::vector<base::EndpointId> targets = config_.peer_domain_reps;
    lk.unlock();

    if (has_digest_to_send && send_digest_cb_) {
        for (const auto &target : targets) {
            try {
                send_digest_cb_(target, digest_to_send);
            } catch (...) {
                // 单个目标发送失败不影响其他目标
            }
        }
    }

    // ----------------------------------------------------------------
    // V3-B: 跨域地址提示发送 + 地址缓存清理（独立方法，内部自行加锁）
    // ----------------------------------------------------------------
    tick_cross_domain_addr_hint_();
}

// ============================================================================
// V3-B: 跨域数据面通道实现
// ============================================================================
//
// 设计要点：
//   - CrossDomainAddrHintPayload 序列化：变长布局，长度前缀字符串
//   - NodeRegistry 跨域地址缓存：独立 mutex，与 entries_ 互不阻塞
//   - resolve_cross_domain_addr：缓存命中 → Pkarr DNS → 全失败 nullopt
//   - ControlPlane.tick_cross_domain_addr_hint_：跨域代表定期发送 + 缓存清理
//
// 向后兼容：
//   - cross_domain_enabled=false 时全部 no-op，行为与 v3.0 一致
//   - 缓存为空时 resolve 返回 nullopt，调用方降级单域调度

// ----------------------------------------------------------------------------
// CrossDomainAddrHintPayload 实现
// ----------------------------------------------------------------------------

bool CrossDomainAddrHintPayload::within_limit(std::size_t max_addr_hints) const noexcept {
    return hints.size() <= max_addr_hints;
}

std::string CrossDomainAddrHintPayload::brief() const {
    return "CrossDomainAddrHintPayload{sender_domain=" + std::to_string(sender_domain_id) +
           ", ttl=" + std::to_string(static_cast<unsigned>(ttl)) +
           ", hints=" + std::to_string(hints.size()) + "}";
}

namespace {
// V3-B 内部辅助：写入 LE 整数
inline void write_u16_le(std::uint8_t *&p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v & 0xFF);
    p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
    p += 2;
}
inline void write_u32_le(std::uint8_t *&p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>(v & 0xFF);
    p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
    p += 4;
}
inline bool read_u16_le(const std::uint8_t *&p, std::size_t &remain, std::uint16_t &out) {
    if (remain < 2) return false;
    out = static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
    p += 2; remain -= 2;
    return true;
}
inline bool read_u32_le(const std::uint8_t *&p, std::size_t &remain, std::uint32_t &out) {
    if (remain < 4) return false;
    out = static_cast<std::uint32_t>(p[0]) |
          (static_cast<std::uint32_t>(p[1]) << 8) |
          (static_cast<std::uint32_t>(p[2]) << 16) |
          (static_cast<std::uint32_t>(p[3]) << 24);
    p += 4; remain -= 4;
    return true;
}

// 写入长度前缀字符串（uint16 长度 + 字节）
bool write_lps(std::uint8_t *&p, std::size_t &cap, const std::string &s) {
    if (s.size() > 65535) return false;
    if (cap < 2 + s.size()) return false;
    write_u16_le(p, static_cast<std::uint16_t>(s.size()));
    std::memcpy(p, s.data(), s.size());
    p += s.size(); cap -= 2 + s.size();
    return true;
}
bool read_lps(const std::uint8_t *&p, std::size_t &remain, std::string &out) {
    std::uint16_t len = 0;
    if (!read_u16_le(p, remain, len)) return false;
    if (remain < len) return false;
    out.assign(reinterpret_cast<const char *>(p), len);
    p += len; remain -= len;
    return true;
}

// 计算单个 TransportAddr 序列化字节数（kind(1) + host_lps + port(2) + custom_lps）
inline std::size_t transport_addr_size(const base::TransportAddr &a) {
    return 1 + 2 + a.host.size() + 2 + 2 + a.custom_payload.size();
}
// 计算单个 RelayUrl 序列化字节数（url_lps）
inline std::size_t relay_url_size(const base::RelayUrl &r) {
    return 2 + r.url().size();
}
// 计算单个 AddrHintEntry（EndpointAddr）序列化字节数
inline std::size_t endpoint_addr_size(const base::EndpointAddr &a) {
    std::size_t s = 32 + 1 + 1;  // endpoint_id + direct_count + relay_count
    for (const auto &d : a.direct_addresses()) s += transport_addr_size(d);
    for (const auto &r : a.relays())         s += relay_url_size(r);
    return s;
}

// 写入 TransportAddr（kind + host_lps + port + custom_lps）
bool write_transport_addr(std::uint8_t *&p, std::size_t &cap, const base::TransportAddr &a) {
    if (cap < 1) return false;
    *p++ = static_cast<std::uint8_t>(a.kind); --cap;
    if (!write_lps(p, cap, a.host)) return false;
    if (cap < 2) return false;
    write_u16_le(p, a.port); cap -= 2;
    if (!write_lps(p, cap, a.custom_payload)) return false;
    return true;
}
bool read_transport_addr(const std::uint8_t *&p, std::size_t &remain, base::TransportAddr &out) {
    if (remain < 1) return false;
    out.kind = static_cast<base::TransportKind>(*p++); --remain;
    if (!read_lps(p, remain, out.host)) return false;
    std::uint16_t port = 0;
    if (!read_u16_le(p, remain, port)) return false;
    out.port = port;
    if (!read_lps(p, remain, out.custom_payload)) return false;
    return true;
}

// 写入 RelayUrl（url_lps）
bool write_relay_url(std::uint8_t *&p, std::size_t &cap, const base::RelayUrl &r) {
    return write_lps(p, cap, r.url());
}
bool read_relay_url(const std::uint8_t *&p, std::size_t &remain, base::RelayUrl &out) {
    std::string url;
    if (!read_lps(p, remain, url)) return false;
    out = base::RelayUrl(std::move(url));
    return true;
}

// 写入单个 AddrHintEntry（endpoint_id + direct_count + relay_count + addrs + urls）
bool write_endpoint_addr(std::uint8_t *&p, std::size_t &cap, const base::EndpointAddr &a) {
    if (a.direct_addresses().size() > 255 || a.relays().size() > 255) return false;
    if (cap < 32 + 1 + 1) return false;
    std::memcpy(p, a.id().data(), 32); p += 32; cap -= 32;
    *p++ = static_cast<std::uint8_t>(a.direct_addresses().size()); --cap;
    *p++ = static_cast<std::uint8_t>(a.relays().size()); --cap;
    for (const auto &d : a.direct_addresses()) {
        if (!write_transport_addr(p, cap, d)) return false;
    }
    for (const auto &r : a.relays()) {
        if (!write_relay_url(p, cap, r)) return false;
    }
    return true;
}
bool read_endpoint_addr(const std::uint8_t *&p, std::size_t &remain, base::EndpointAddr &out) {
    if (remain < 32 + 1 + 1) return false;
    out = base::EndpointAddr(base::EndpointId::from_bytes(
        std::span<const std::uint8_t>(p, 32)));
    p += 32; remain -= 32;
    std::uint8_t d_count = *p++; --remain;
    std::uint8_t r_count = *p++; --remain;
    for (std::uint8_t i = 0; i < d_count; ++i) {
        base::TransportAddr ta;
        if (!read_transport_addr(p, remain, ta)) return false;
        out.add_direct_address(std::move(ta));
    }
    for (std::uint8_t i = 0; i < r_count; ++i) {
        base::RelayUrl ru;
        if (!read_relay_url(p, remain, ru)) return false;
        out.add_relay(std::move(ru));
    }
    return true;
}

// 单帧总长上限（4KB，跨域带宽约束，规范 §4.1.3）
constexpr std::size_t kAddrHintMaxFrameSize = 4096;
// 帧头固定字节数（不含签名，签名由传输层在帧尾追加）
constexpr std::size_t kAddrHintHeaderSize = 4 + 1 + 1 + 3 + 32;
}  // anonymous namespace

std::size_t CrossDomainAddrHintPayload::serialize(std::uint8_t *out, std::size_t cap) const {
    if (out == nullptr) return 0;
    if (hints.size() > 255) return 0;

    // 预计算总长，校验容量与帧上限
    std::size_t total = kAddrHintHeaderSize;
    for (const auto &h : hints) total += endpoint_addr_size(h);
    if (total > kAddrHintMaxFrameSize) return 0;
    if (cap < total) return 0;

    std::uint8_t *p = out;
    std::size_t cap_left = cap;
    write_u32_le(p, sender_domain_id);
    *p++ = static_cast<std::uint8_t>(hints.size());  // hint_count
    *p++ = ttl;                                       // ttl
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;            // reserved(3)
    std::memcpy(p, sender_endpoint_id.data(), 32); p += 32;
    cap_left -= kAddrHintHeaderSize;

    for (const auto &h : hints) {
        if (!write_endpoint_addr(p, cap_left, h)) return 0;
    }
    return static_cast<std::size_t>(p - out);
}

std::size_t CrossDomainAddrHintPayload::deserialize(const std::uint8_t *in, std::size_t len,
                                                     CrossDomainAddrHintPayload &out_payload) {
    if (in == nullptr) return 0;
    if (len < kAddrHintHeaderSize) return 0;

    const std::uint8_t *p = in;
    std::size_t remain = len;
    if (!read_u32_le(p, remain, out_payload.sender_domain_id)) return 0;
    if (remain < 1) return 0;
    std::uint8_t hint_count = *p++; --remain;
    if (remain < 1) return 0;
    out_payload.ttl = *p++; --remain;
    if (remain < 3) return 0;
    p += 3; remain -= 3;  // reserved
    out_payload.sender_endpoint_id = base::EndpointId::from_bytes(
        std::span<const std::uint8_t>(p, 32));
    p += 32; remain -= 32;

    out_payload.hints.clear();
    out_payload.hints.reserve(hint_count);
    for (std::uint8_t i = 0; i < hint_count; ++i) {
        base::EndpointAddr addr;
        if (!read_endpoint_addr(p, remain, addr)) return 0;
        out_payload.hints.push_back(std::move(addr));
    }

    std::size_t consumed = static_cast<std::size_t>(p - in);
    if (consumed > kAddrHintMaxFrameSize) return 0;  // 帧上限守护
    return consumed;
}

// ----------------------------------------------------------------------------
// NodeRegistry V3-B 跨域地址缓存实现
// ----------------------------------------------------------------------------

void NodeRegistry::cache_cross_domain_addr(const base::EndpointId &endpoint_id,
                                            base::EndpointAddr addr) {
    std::lock_guard<std::mutex> lk(addr_cache_mu_);
    auto &entry = cross_domain_addr_cache_[endpoint_id];
    entry.addr = std::move(addr);
    entry.cached_at = clock_();
}

std::optional<base::EndpointAddr> NodeRegistry::get_cross_domain_addr(
    const base::EndpointId &endpoint_id) const {
    std::lock_guard<std::mutex> lk(addr_cache_mu_);
    auto it = cross_domain_addr_cache_.find(endpoint_id);
    if (it == cross_domain_addr_cache_.end()) return std::nullopt;
    return it->second.addr;
}

std::optional<base::EndpointAddr> NodeRegistry::resolve_cross_domain_addr(
    const base::EndpointId &endpoint_id,
    address_lookup::AddressLookup *lookup) const {
    // 机制 A：本地地址缓存命中（CrossDomainAddrHint 写入）
    {
        std::lock_guard<std::mutex> lk(addr_cache_mu_);
        auto it = cross_domain_addr_cache_.find(endpoint_id);
        if (it != cross_domain_addr_cache_.end()) {
            return it->second.addr;
        }
    }
    // 机制 B：Pkarr DNS 查询（lookup 可为 nullptr，跳过 DNS）
    if (lookup != nullptr) {
        try {
            auto addr_opt = lookup->lookup(endpoint_id);
            if (addr_opt.has_value()) {
                // DNS 查询成功，回填缓存（加速下次查询）
                std::lock_guard<std::mutex> lk(addr_cache_mu_);
                auto &entry = cross_domain_addr_cache_[endpoint_id];
                entry.addr = *addr_opt;
                entry.cached_at = clock_();
                return *addr_opt;
            }
        } catch (...) {
            // DNS 查询异常，降级到机制 C
        }
    }
    // 机制 C：全失败返回 nullopt（调用方降级单域调度或构造仅含 relays 的兜底 EndpointAddr）
    return std::nullopt;
}

std::size_t NodeRegistry::prune_cross_domain_addr_cache(std::chrono::seconds timeout) {
    std::lock_guard<std::mutex> lk(addr_cache_mu_);
    std::size_t pruned = 0;
    auto now = clock_();
    for (auto it = cross_domain_addr_cache_.begin(); it != cross_domain_addr_cache_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.cached_at);
        if (age > timeout) {
            it = cross_domain_addr_cache_.erase(it);
            ++pruned;
        } else {
            ++it;
        }
    }
    return pruned;
}

std::size_t NodeRegistry::cross_domain_addr_cache_size() const noexcept {
    std::lock_guard<std::mutex> lk(addr_cache_mu_);
    return cross_domain_addr_cache_.size();
}

// ----------------------------------------------------------------------------
// ControlPlane V3-B 接口实现
// ----------------------------------------------------------------------------

void ControlPlane::set_send_addr_hint_callback(SendAddrHintCallback cb) {
    std::lock_guard<std::mutex> lk(mu_);
    send_addr_hint_cb_ = std::move(cb);
}

void ControlPlane::set_local_addr_provider(
    std::function<std::optional<base::EndpointAddr>(const base::EndpointId &)> cb) {
    std::lock_guard<std::mutex> lk(mu_);
    addr_provider_ = std::move(cb);
}

std::size_t ControlPlane::on_addr_hint_received(const CrossDomainAddrHintPayload &payload) {
    // V3-B: 跨域未启用时 no-op（向后兼容）
    if (!config_.cross_domain_enabled || config_.domain_id == 0) {
        return 0;
    }
    // 同域提示不处理（避免环路，与 on_digest_received 一致）
    if (payload.sender_domain_id == config_.domain_id) {
        return 0;
    }
    std::size_t cached = 0;
    for (const auto &hint : payload.hints) {
        // 仅缓存有效 EndpointAddr（至少有 relay 或 direct 之一）
        if (hint.has_relay() || hint.has_direct()) {
            registry_.cache_cross_domain_addr(hint.id(), hint);
            ++cached;
        }
    }
    return cached;
}

CrossDomainAddrHintPayload ControlPlane::build_addr_hint(
    const base::EndpointId &self_id,
    std::uint32_t self_domain) const {
    // V3-B: 从 registry 提取本域在线节点 + 按 sort_score 降序取前 max_addr_hints
    // 节点 EndpointAddr 由 addr_provider_ 回调提供（本节点由 Endpoint::my_addr 注入）
    CrossDomainAddrHintPayload payload;
    payload.sender_domain_id = self_domain;
    payload.ttl = config_.cross_domain_ttl;
    payload.sender_endpoint_id = self_id;

    auto all = registry_.snapshot();
    std::vector<NodeRegistryEntry> domain_nodes;
    for (const auto &entry : all) {
        if (!entry.is_cross_domain && entry.state != NodeState::Offline) {
            domain_nodes.push_back(entry);
        }
    }
    std::sort(domain_nodes.begin(), domain_nodes.end(),
              [](const NodeRegistryEntry &a, const NodeRegistryEntry &b) {
                  return a.sort_score() > b.sort_score();
              });

    std::size_t limit = (std::min)(domain_nodes.size(), config_.max_addr_hints);
    payload.hints.reserve(limit);

    // 锁内拷贝 addr_provider_（避免回调期间被替换）
    std::function<std::optional<base::EndpointAddr>(const base::EndpointId &)> provider;
    {
        std::lock_guard<std::mutex> lk(mu_);
        provider = addr_provider_;
    }

    for (std::size_t i = 0; i < limit; ++i) {
        const auto &entry = domain_nodes[i];
        if (!provider) continue;
        auto addr_opt = provider(entry.profile.endpoint_id);
        if (addr_opt.has_value()) {
            // 确保 EndpointAddr 的 id 字段与节点 EndpointId 一致
            base::EndpointAddr addr = *addr_opt;
            if (addr.id() != entry.profile.endpoint_id) {
                // 提供者返回的 id 不匹配，构造一个新 EndpointAddr
                base::EndpointAddr fixed(entry.profile.endpoint_id);
                for (const auto &r : addr.relays()) fixed.add_relay(r);
                for (const auto &d : addr.direct_addresses()) fixed.add_direct_address(d);
                addr = std::move(fixed);
            }
            payload.hints.push_back(std::move(addr));
        }
    }
    return payload;
}

void ControlPlane::tick_cross_domain_addr_hint_() {
    // V3-B: 跨域代表定期发送 AddrHint + 所有节点定期清理地址缓存
    // 由 tick_cross_domain_ 末尾调用（已 unlock），本方法内部自行加锁
    if (!config_.cross_domain_enabled || config_.domain_id == 0) {
        return;
    }

    std::unique_lock<std::mutex> lk(mu_);
    auto now = clock_();

    // 阶段 1：跨域地址缓存清理（所有节点都做，与跨域节点 stale 清理解耦）
    auto prune_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_cross_domain_addr_prune_);
    bool need_prune = (prune_elapsed >= config_.cross_domain_addr_cache_timeout);
    if (need_prune) {
        last_cross_domain_addr_prune_ = now;
    }

    // 阶段 2：跨域代表发送 AddrHint（与 Digest 同周期，紧随其后）
    auto hint_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_cross_domain_addr_hint_);
    bool need_send_hint = (hint_elapsed >= config_.cross_domain_aggregate_interval) &&
                          is_self_cross_domain_rep_.load(std::memory_order_acquire) &&
                          send_addr_hint_cb_ &&
                          !config_.peer_domain_reps.empty();

    CrossDomainAddrHintPayload hint_to_send;
    bool has_hint_to_send = false;
    if (need_send_hint) {
        hint_to_send = build_addr_hint(self_id_, config_.domain_id);
        has_hint_to_send = !hint_to_send.hints.empty();
        last_cross_domain_addr_hint_ = now;  // 仅在实际发送时更新
    } else if (hint_elapsed >= config_.cross_domain_aggregate_interval) {
        // 非代表节点也更新时间戳，避免每 tick 都重算
        last_cross_domain_addr_hint_ = now;
    }

    std::vector<base::EndpointId> targets = config_.peer_domain_reps;
    lk.unlock();

    // 锁外清理缓存（避免持锁期间回调）
    if (need_prune) {
        registry_.prune_cross_domain_addr_cache(config_.cross_domain_addr_cache_timeout);
    }

    // 锁外发送 AddrHint（避免回调中再次获取 mu_ 导致死锁）
    if (has_hint_to_send && send_addr_hint_cb_) {
        for (const auto &target : targets) {
            try {
                send_addr_hint_cb_(target, hint_to_send);
            } catch (...) {
                // 单个目标发送失败不影响其他目标
            }
        }
    }
}

}  // namespace linoh
