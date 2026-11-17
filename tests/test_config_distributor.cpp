// test_config_distributor.cpp — 分布式配置分发器单元测试（v2.1 Phase 2）
//
// 覆盖：
//   1. ConfigEntry / ConfigSnapshot / ConfigDelta 序列化 roundtrip
//   2. 本地配置操作（set_local / get_local / delete_local / current_epoch）
//   3. Ed25519 签名验证（合法/篡改/错误公钥）
//   4. CRDT LWW 合并（高版本覆盖 / 低版本跳过 / 同版本跳过）
//   5. epoch 防回退（snapshot / delta）
//   6. gossip 传播（build_delta_for / on_config_delta_received）
//   7. 落后检测（lagging_nodes / update_node_config_epoch）
//   8. 订阅热更新（set_local / apply_delta / delete / 前缀匹配 / 取消订阅）
//   9. 历史回滚（rollback_to / history_size）

#include "linoh/config_distributor.hpp"
#include "linoh/base/key.hpp"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#define CHECK(cond) do { \
    ++total; \
    if (!(cond)) { \
        std::cerr << "FAIL: " << #cond << " (line " << __LINE__ << ")" << std::endl; \
        ++failed; \
    } \
} while(0)

static int total = 0;
static int failed = 0;

using namespace linoh;
using namespace linoh::base;

// ============================================================================
// 辅助函数
// ============================================================================

static EndpointId make_id(std::uint8_t seed) {
    std::array<uint8_t, 32> bytes{};
    bytes[0] = seed;
    bytes[31] = seed;
    return EndpointId::from_bytes(bytes);
}

/// 构造已签名的 ConfigSnapshot
static ConfigSnapshot make_signed_snapshot(
    std::uint64_t epoch,
    const std::vector<std::pair<std::string, std::string>> &kvs,
    const SecretKey &orch_key,
    std::uint64_t base_version = 1) {

    ConfigSnapshot snap;
    snap.epoch = epoch;
    snap.created_at = std::chrono::system_clock::now();
    snap.origin = orch_key.public_key();

    std::uint64_t ver = base_version;
    for (const auto &[k, v] : kvs) {
        ConfigEntry e;
        e.key = k;
        e.value = v;
        e.version = ver++;
        e.updated_at = snap.created_at;
        snap.entries.push_back(e);
    }

    auto sig_data = snap.signing_data();
    auto sig = orch_key.sign(sig_data);
    std::memcpy(snap.signature.data(), sig.data(), 64);
    return snap;
}

/// 构造已签名的 ConfigDelta
/// @param base_version 第一个 entry 的 version，后续 entry 递增
static ConfigDelta make_signed_delta(
    std::uint64_t from_epoch,
    std::uint64_t to_epoch,
    const std::vector<std::pair<std::string, std::string>> &changes,
    const std::vector<std::string> &deletions,
    const SecretKey &orch_key,
    std::uint64_t base_version = 1) {

    ConfigDelta delta;
    delta.from_epoch = from_epoch;
    delta.to_epoch = to_epoch;

    auto now = std::chrono::system_clock::now();
    std::uint64_t ver = base_version;
    for (const auto &[k, v] : changes) {
        ConfigEntry e;
        e.key = k;
        e.value = v;
        e.version = ver++;
        e.updated_at = now;
        delta.changes.push_back(e);
    }
    delta.deletions = deletions;

    auto sig_data = delta.signing_data();
    auto sig = orch_key.sign(sig_data);
    std::memcpy(delta.signature.data(), sig.data(), 64);
    return delta;
}

// ============================================================================
// 1. ConfigEntry 序列化
// ============================================================================

void test_config_entry_roundtrip() {
    std::cout << "[test] ConfigEntry serialize/parse roundtrip" << std::endl;
    ConfigEntry e;
    e.key = "control_plane.heartbeat_interval";
    e.value = "5";
    e.version = 42;
    e.updated_at = std::chrono::system_clock::now();

    auto bytes = e.serialize();
    CHECK(!bytes.empty());

    ConfigEntry parsed;
    auto consumed = ConfigEntry::parse(bytes, parsed);
    CHECK(consumed == bytes.size());
    CHECK(parsed.key == e.key);
    CHECK(parsed.value == e.value);
    CHECK(parsed.version == e.version);
}

void test_config_entry_empty_strings() {
    std::cout << "[test] ConfigEntry empty key/value" << std::endl;
    ConfigEntry e;
    e.key = "";
    e.value = "";
    e.version = 0;

    auto bytes = e.serialize();
    ConfigEntry parsed;
    auto consumed = ConfigEntry::parse(bytes, parsed);
    CHECK(consumed == bytes.size());
    CHECK(parsed.key.empty());
    CHECK(parsed.value.empty());
    CHECK(parsed.version == 0);
}

void test_config_entry_parse_insufficient() {
    std::cout << "[test] ConfigEntry parse insufficient data returns 0" << std::endl;
    std::vector<uint8_t> short_data{0x01, 0x02};
    ConfigEntry parsed;
    CHECK(ConfigEntry::parse(short_data, parsed) == 0);
}

// ============================================================================
// 2. ConfigSnapshot 序列化
// ============================================================================

void test_config_snapshot_roundtrip() {
    std::cout << "[test] ConfigSnapshot serialize/parse roundtrip" << std::endl;
    auto orch_key = SecretKey::generate();

    ConfigSnapshot snap;
    snap.epoch = 7;
    snap.created_at = std::chrono::system_clock::now();
    snap.origin = orch_key.public_key();

    ConfigEntry e1;
    e1.key = "control_plane.heartbeat_interval";
    e1.value = "5";
    e1.version = 1;
    e1.updated_at = snap.created_at;

    ConfigEntry e2;
    e2.key = "control_plane.gossip_fanout";
    e2.value = "3";
    e2.version = 2;
    e2.updated_at = snap.created_at;

    snap.entries = {e1, e2};

    auto sig_data = snap.signing_data();
    auto sig = orch_key.sign(sig_data);
    std::memcpy(snap.signature.data(), sig.data(), 64);

    auto bytes = snap.serialize();
    CHECK(!bytes.empty());

    ConfigSnapshot parsed;
    auto consumed = ConfigSnapshot::parse(bytes, parsed);
    CHECK(consumed == bytes.size());
    CHECK(parsed.epoch == snap.epoch);
    CHECK(parsed.origin == snap.origin);
    CHECK(parsed.entries.size() == 2);
    CHECK(parsed.entries[0].key == "control_plane.heartbeat_interval");
    CHECK(parsed.entries[0].value == "5");
    CHECK(parsed.entries[1].key == "control_plane.gossip_fanout");
    CHECK(parsed.entries[1].value == "3");
    CHECK(std::memcmp(parsed.signature.data(), snap.signature.data(), 64) == 0);
}

void test_config_snapshot_signing_data_deterministic() {
    std::cout << "[test] ConfigSnapshot signing_data deterministic" << std::endl;
    auto orch_key = SecretKey::generate();

    ConfigSnapshot s1, s2;
    s1.epoch = 1;
    s2.epoch = 1;
    s1.created_at = std::chrono::system_clock::now();
    s2.created_at = s1.created_at;
    s1.origin = orch_key.public_key();
    s2.origin = s1.origin;

    ConfigEntry e;
    e.key = "k";
    e.value = "v";
    e.version = 1;
    e.updated_at = s1.created_at;
    s1.entries = {e};
    s2.entries = {e};

    auto d1 = s1.signing_data();
    auto d2 = s2.signing_data();
    CHECK(d1 == d2);
}

// ============================================================================
// 3. ConfigDelta 序列化
// ============================================================================

void test_config_delta_roundtrip() {
    std::cout << "[test] ConfigDelta serialize/parse roundtrip" << std::endl;
    auto orch_key = SecretKey::generate();

    ConfigDelta delta;
    delta.from_epoch = 3;
    delta.to_epoch = 5;

    ConfigEntry e;
    e.key = "control_plane.stale_timeout";
    e.value = "30";
    e.version = 4;
    e.updated_at = std::chrono::system_clock::now();
    delta.changes = {e};
    delta.deletions = {"old_key"};

    auto sig_data = delta.signing_data();
    auto sig = orch_key.sign(sig_data);
    std::memcpy(delta.signature.data(), sig.data(), 64);

    auto bytes = delta.serialize();
    CHECK(!bytes.empty());

    ConfigDelta parsed;
    auto consumed = ConfigDelta::parse(bytes, parsed);
    CHECK(consumed == bytes.size());
    CHECK(parsed.from_epoch == 3);
    CHECK(parsed.to_epoch == 5);
    CHECK(parsed.changes.size() == 1);
    CHECK(parsed.changes[0].key == "control_plane.stale_timeout");
    CHECK(parsed.changes[0].value == "30");
    CHECK(parsed.deletions.size() == 1);
    CHECK(parsed.deletions[0] == "old_key");
    CHECK(std::memcmp(parsed.signature.data(), delta.signature.data(), 64) == 0);
}

void test_config_delta_is_full() {
    std::cout << "[test] ConfigDelta is_full when from_epoch=0" << std::endl;
    ConfigDelta d1;
    d1.from_epoch = 0;
    CHECK(d1.is_full());

    ConfigDelta d2;
    d2.from_epoch = 1;
    CHECK(!d2.is_full());
}

// ============================================================================
// 4. 本地配置操作
// ============================================================================

void test_distributor_set_local_increments_epoch() {
    std::cout << "[test] set_local increments epoch" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    CHECK(dist.current_epoch() == 0);
    dist.set_local("k1", "v1", key);
    CHECK(dist.current_epoch() == 1);
    dist.set_local("k2", "v2", key);
    CHECK(dist.current_epoch() == 2);
    dist.set_local("k1", "v1_updated", key);
    CHECK(dist.current_epoch() == 3);
}

void test_distributor_get_local() {
    std::cout << "[test] get_local returns value" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    dist.set_local("heartbeat_interval", "5", key);
    auto val = dist.get_local("heartbeat_interval");
    CHECK(val.has_value());
    CHECK(*val == "5");

    CHECK(!dist.get_local("nonexistent").has_value());
}

void test_distributor_delete_local() {
    std::cout << "[test] delete_local removes entry" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    dist.set_local("k1", "v1", key);
    CHECK(dist.get_local("k1").has_value());

    dist.delete_local("k1", key);
    CHECK(!dist.get_local("k1").has_value());
    CHECK(dist.current_epoch() == 2);  // set=1, delete=2
}

void test_distributor_delete_nonexistent_noop() {
    std::cout << "[test] delete_local on nonexistent is no-op" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    dist.delete_local("nonexistent", key);
    CHECK(dist.current_epoch() == 0);  // 无变更
}

void test_distributor_get_snapshot() {
    std::cout << "[test] get_snapshot returns current state" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    dist.set_local("k1", "v1", key);
    dist.set_local("k2", "v2", key);

    auto snap = dist.get_snapshot();
    CHECK(snap.epoch == 2);
    CHECK(snap.entries.size() == 2);
}

// ============================================================================
// 5. 签名验证
// ============================================================================

void test_apply_snapshot_valid_signature() {
    std::cout << "[test] apply_snapshot accepts valid signature" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto snap = make_signed_snapshot(1, {{"k1", "v1"}, {"k2", "v2"}}, orch_key);
    CHECK(dist.apply_snapshot(snap, orch_pub));
    CHECK(dist.current_epoch() == 1);
    CHECK(dist.get_local("k1").has_value());
    CHECK(*dist.get_local("k1") == "v1");
    CHECK(*dist.get_local("k2") == "v2");
}

void test_apply_snapshot_invalid_signature_rejected() {
    std::cout << "[test] apply_snapshot rejects tampered signature" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto snap = make_signed_snapshot(1, {{"k1", "v1"}}, orch_key);
    // 篡改签名
    snap.signature[0] ^= 0xFF;

    CHECK(!dist.apply_snapshot(snap, orch_pub));
    CHECK(dist.current_epoch() == 0);
    CHECK(!dist.get_local("k1").has_value());
}

void test_apply_snapshot_wrong_pubkey_rejected() {
    std::cout << "[test] apply_snapshot rejects wrong pubkey" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto other_key = SecretKey::generate();

    auto snap = make_signed_snapshot(1, {{"k1", "v1"}}, orch_key);
    CHECK(!dist.apply_snapshot(snap, other_key.public_key()));
}

void test_apply_delta_valid_signature() {
    std::cout << "[test] apply_delta accepts valid signature" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto delta = make_signed_delta(0, 1, {{"k1", "v1"}}, {}, orch_key);
    CHECK(dist.apply_delta(delta, orch_pub));
    CHECK(dist.current_epoch() == 1);
    CHECK(*dist.get_local("k1") == "v1");
}

void test_apply_delta_invalid_signature_rejected() {
    std::cout << "[test] apply_delta rejects tampered signature" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto delta = make_signed_delta(0, 1, {{"k1", "v1"}}, {}, orch_key);
    delta.signature[0] ^= 0xFF;

    CHECK(!dist.apply_delta(delta, orch_pub));
    CHECK(dist.current_epoch() == 0);
}

// ============================================================================
// 6. CRDT LWW 合并
// ============================================================================

void test_apply_delta_lww_higher_version_wins() {
    std::cout << "[test] LWW: higher version overwrites" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    // 初始设置 k1=v1, version=1
    auto d1 = make_signed_delta(0, 1, {{"k1", "v1"}}, {}, orch_key);
    CHECK(dist.apply_delta(d1, orch_pub));
    CHECK(*dist.get_local("k1") == "v1");

    // 应用 delta: k1=v2, version=3（更高版本）
    auto d2 = make_signed_delta(1, 2, {{"k1", "v2"}}, {}, orch_key, 3);
    CHECK(dist.apply_delta(d2, orch_pub));
    CHECK(*dist.get_local("k1") == "v2");
}

void test_apply_delta_lww_lower_version_skipped() {
    std::cout << "[test] LWW: lower version skipped" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    // 初始设置 k1=v2, version=5
    auto d1 = make_signed_delta(0, 1, {{"k1", "v2"}}, {}, orch_key, 5);
    CHECK(dist.apply_delta(d1, orch_pub));

    // 应用 delta: k1=old_value, version=3（更低版本）→ 应跳过
    auto d2 = make_signed_delta(1, 2, {{"k1", "old_value"}}, {}, orch_key, 3);
    CHECK(dist.apply_delta(d2, orch_pub));
    CHECK(*dist.get_local("k1") == "v2");  // 保持高版本值
}

void test_apply_delta_lww_equal_version_skipped() {
    std::cout << "[test] LWW: equal version skipped" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto d1 = make_signed_delta(0, 1, {{"k1", "v1"}}, {}, orch_key, 5);
    CHECK(dist.apply_delta(d1, orch_pub));

    auto d2 = make_signed_delta(1, 2, {{"k1", "v2"}}, {}, orch_key, 5);
    CHECK(dist.apply_delta(d2, orch_pub));
    CHECK(*dist.get_local("k1") == "v1");  // 同版本不覆盖
}

void test_apply_delta_deletion() {
    std::cout << "[test] apply_delta processes deletions" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto d1 = make_signed_delta(0, 1, {{"k1", "v1"}, {"k2", "v2"}}, {}, orch_key);
    CHECK(dist.apply_delta(d1, orch_pub));

    auto d2 = make_signed_delta(1, 2, {}, {"k1"}, orch_key);
    CHECK(dist.apply_delta(d2, orch_pub));
    CHECK(!dist.get_local("k1").has_value());
    CHECK(dist.get_local("k2").has_value());
}

// ============================================================================
// 7. epoch 防回退
// ============================================================================

void test_apply_snapshot_epoch_rollback_rejected() {
    std::cout << "[test] apply_snapshot rejects epoch rollback" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto s1 = make_signed_snapshot(5, {{"k1", "v1"}}, orch_key);
    CHECK(dist.apply_snapshot(s1, orch_pub));
    CHECK(dist.current_epoch() == 5);

    auto s2 = make_signed_snapshot(3, {{"k1", "v2"}}, orch_key);
    CHECK(!dist.apply_snapshot(s2, orch_pub));  // 3 <= 5
    CHECK(dist.current_epoch() == 5);
    CHECK(*dist.get_local("k1") == "v1");  // 未变更
}

void test_apply_delta_epoch_rollback_rejected() {
    std::cout << "[test] apply_delta rejects epoch rollback" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto d1 = make_signed_delta(0, 5, {{"k1", "v1"}}, {}, orch_key);
    CHECK(dist.apply_delta(d1, orch_pub));

    auto d2 = make_signed_delta(3, 4, {{"k1", "v2"}}, {}, orch_key);
    CHECK(!dist.apply_delta(d2, orch_pub));  // to_epoch=4 <= 5
    CHECK(*dist.get_local("k1") == "v1");
}

void test_apply_snapshot_equal_epoch_rejected() {
    std::cout << "[test] apply_snapshot rejects equal epoch" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto s1 = make_signed_snapshot(3, {{"k1", "v1"}}, orch_key);
    CHECK(dist.apply_snapshot(s1, orch_pub));

    auto s2 = make_signed_snapshot(3, {{"k1", "v2"}}, orch_key);
    CHECK(!dist.apply_snapshot(s2, orch_pub));  // 3 <= 3
}

// ============================================================================
// 8. gossip 传播
// ============================================================================

void test_build_delta_for_no_cache_returns_nullopt() {
    std::cout << "[test] build_delta_for returns nullopt without cached delta" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto target = make_id(1);

    CHECK(!dist.build_delta_for(target).has_value());
}

void test_build_delta_for_returns_cached_delta() {
    std::cout << "[test] build_delta_for returns cached delta after apply_delta" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto delta = make_signed_delta(0, 1, {{"k1", "v1"}}, {}, orch_key);
    CHECK(dist.apply_delta(delta, orch_pub));

    auto target = make_id(5);
    auto result = dist.build_delta_for(target);
    CHECK(result.has_value());
    CHECK(result->to_epoch == 1);
    CHECK(result->changes.size() == 1);
}

void test_build_delta_for_target_uptodate_returns_nullopt() {
    std::cout << "[test] build_delta_for returns nullopt for up-to-date target" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto delta = make_signed_delta(0, 3, {{"k1", "v1"}}, {}, orch_key);
    CHECK(dist.apply_delta(delta, orch_pub));

    auto target = make_id(5);
    dist.update_node_config_epoch(target, 3);  // 目标已是 epoch 3

    CHECK(!dist.build_delta_for(target).has_value());
}

void test_on_config_delta_received_updates_node_epoch() {
    std::cout << "[test] on_config_delta_received updates source node epoch" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto source = make_id(7);
    auto delta = make_signed_delta(0, 5, {{"k1", "v1"}}, {}, orch_key);

    dist.on_config_delta_received(delta, source, orch_pub);

    // source 的 config_epoch 应被更新为 5
    auto lagging = dist.lagging_nodes(1);
    // source epoch=5, local epoch=5 → 不落后
    CHECK(std::find(lagging.begin(), lagging.end(), source) == lagging.end());
}

// ============================================================================
// 9. 落后检测
// ============================================================================

void test_lagging_nodes_empty() {
    std::cout << "[test] lagging_nodes empty when no nodes tracked" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});

    CHECK(dist.lagging_nodes(2).empty());
}

void test_lagging_nodes_detects_behind() {
    std::cout << "[test] lagging_nodes detects nodes behind threshold" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    // 本地 epoch 推到 5
    auto delta = make_signed_delta(0, 5, {{"k1", "v1"}}, {}, orch_key);
    CHECK(dist.apply_delta(delta, orch_pub));

    // 节点 A epoch=3（落后 2）
    auto node_a = make_id(1);
    dist.update_node_config_epoch(node_a, 3);

    // 节点 B epoch=5（不落后）
    auto node_b = make_id(2);
    dist.update_node_config_epoch(node_b, 5);

    auto lagging = dist.lagging_nodes(2);
    CHECK(lagging.size() == 1);
    CHECK(lagging[0] == node_a);
}

void test_update_node_config_epoch_monotonic() {
    std::cout << "[test] update_node_config_epoch is monotonic (keeps higher)" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    auto delta = make_signed_delta(0, 5, {{"k1", "v1"}}, {}, orch_key);
    CHECK(dist.apply_delta(delta, orch_pub));

    auto node = make_id(1);
    dist.update_node_config_epoch(node, 4);
    dist.update_node_config_epoch(node, 2);  // 更低，应被忽略

    auto lagging = dist.lagging_nodes(1);
    // node epoch=4, local=5 → 落后 1，在阈值 1 内
    // 但 (5-4)=1 >= 1 → 落后
    CHECK(lagging.size() == 1);
}

// ============================================================================
// 10. 订阅热更新
// ============================================================================

void test_subscribe_set_local_notification() {
    std::cout << "[test] subscribe receives set_local changes" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    std::atomic<int> notify_count{0};
    std::string received_key, received_old, received_new;

    dist.subscribe("control_plane.", [&](const std::string &k,
                                          const std::string &old_v,
                                          const std::string &new_v) {
        ++notify_count;
        received_key = k;
        received_old = old_v;
        received_new = new_v;
    });

    dist.set_local("control_plane.heartbeat_interval", "5", key);

    CHECK(notify_count.load() == 1);
    CHECK(received_key == "control_plane.heartbeat_interval");
    CHECK(received_old.empty());  // 新增
    CHECK(received_new == "5");
}

void test_subscribe_apply_delta_notification() {
    std::cout << "[test] subscribe receives apply_delta changes" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();

    std::atomic<int> notify_count{0};
    dist.subscribe("", [&](const std::string &, const std::string &, const std::string &) {
        ++notify_count;
    });

    auto delta = make_signed_delta(0, 1, {{"k1", "v1"}}, {}, orch_key);
    CHECK(dist.apply_delta(delta, orch_pub));

    CHECK(notify_count.load() == 1);
}

void test_subscribe_delete_notification() {
    std::cout << "[test] subscribe receives delete notifications" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    dist.set_local("k1", "v1", key);

    std::atomic<int> delete_count{0};
    std::string deleted_key, old_val;
    dist.subscribe("", [&](const std::string &k, const std::string &old_v, const std::string &new_v) {
        if (new_v.empty()) {
            ++delete_count;
            deleted_key = k;
            old_val = old_v;
        }
    });

    dist.delete_local("k1", key);

    CHECK(delete_count.load() == 1);
    CHECK(deleted_key == "k1");
    CHECK(old_val == "v1");
}

void test_subscribe_prefix_match() {
    std::cout << "[test] subscribe only matches key prefix" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    std::atomic<int> cp_count{0};
    std::atomic<int> other_count{0};

    dist.subscribe("control_plane.", [&](const std::string &, const std::string &, const std::string &) {
        ++cp_count;
    });
    dist.subscribe("relay.", [&](const std::string &, const std::string &, const std::string &) {
        ++other_count;
    });

    dist.set_local("control_plane.heartbeat_interval", "5", key);
    dist.set_local("relay.pool_size", "10", key);
    dist.set_local("unknown.key", "x", key);

    CHECK(cp_count.load() == 1);
    CHECK(other_count.load() == 1);
}

void test_unsubscribe_stops_notifications() {
    std::cout << "[test] unsubscribe stops notifications" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    std::atomic<int> count{0};
    auto handle = dist.subscribe("", [&](const std::string &, const std::string &, const std::string &) {
        ++count;
    });

    dist.set_local("k1", "v1", key);
    CHECK(count.load() == 1);

    dist.unsubscribe(handle);
    dist.set_local("k2", "v2", key);
    CHECK(count.load() == 1);  // 不再通知
}

void test_subscribe_empty_prefix_matches_all() {
    std::cout << "[test] subscribe with empty prefix matches all keys" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    std::atomic<int> count{0};
    dist.subscribe("", [&](const std::string &, const std::string &, const std::string &) {
        ++count;
    });

    dist.set_local("k1", "v1", key);
    dist.set_local("k2", "v2", key);
    dist.set_local("k1", "v1_updated", key);

    CHECK(count.load() == 3);
}

// ============================================================================
// 11. 历史回滚
// ============================================================================

void test_history_size_increases() {
    std::cout << "[test] history_size increases with set_local" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    CHECK(dist.history_size() == 0);
    dist.set_local("k1", "v1", key);
    CHECK(dist.history_size() == 1);
    dist.set_local("k2", "v2", key);
    CHECK(dist.history_size() == 2);
}

void test_rollback_to_restores_config() {
    std::cout << "[test] rollback_to restores previous config" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    // epoch=1: k1=v1
    dist.set_local("k1", "v1", key);
    // epoch=2: k1=v2
    dist.set_local("k1", "v2", key);
    // epoch=3: k2=v3
    dist.set_local("k2", "v3", key);

    CHECK(*dist.get_local("k1") == "v2");
    CHECK(dist.current_epoch() == 3);

    // 回滚到 epoch=1（k1=v1, 无 k2）
    CHECK(dist.rollback_to(1, key));

    // 回滚创建新 epoch=4
    CHECK(dist.current_epoch() == 4);
    CHECK(*dist.get_local("k1") == "v1");
    CHECK(!dist.get_local("k2").has_value());  // k2 不在 epoch=1
}

void test_rollback_to_nonexistent_returns_false() {
    std::cout << "[test] rollback_to nonexistent epoch returns false" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    dist.set_local("k1", "v1", key);
    CHECK(!dist.rollback_to(99, key));
}

void test_history_max_10() {
    std::cout << "[test] history capped at 10 entries" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    for (int i = 0; i < 15; ++i) {
        dist.set_local("k", std::to_string(i), key);
    }

    CHECK(dist.history_size() == 10);
}

// ============================================================================
// 12. 并发安全（基础 smoke）
// ============================================================================

void test_concurrent_set_local() {
    std::cout << "[test] concurrent set_local is thread-safe" << std::endl;
    NodeRegistry reg;
    ConfigDistributor dist(reg, ControlPlaneConfig{});
    auto key = SecretKey::generate();

    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&dist, &key, t]() {
            for (int i = 0; i < 10; ++i) {
                dist.set_local("k" + std::to_string(t),
                               "v" + std::to_string(i), key);
            }
        });
    }
    for (auto &th : threads) th.join();

    // 4 线程 × 10 次 = 40 次 set_local
    CHECK(dist.current_epoch() == 40);
    CHECK(dist.get_local("k0").has_value());
    CHECK(dist.get_local("k3").has_value());
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " test_config_distributor (v2.1 Phase 2)" << std::endl;
    std::cout << "========================================" << std::endl;

    // 1. ConfigEntry 序列化
    test_config_entry_roundtrip();
    test_config_entry_empty_strings();
    test_config_entry_parse_insufficient();

    // 2. ConfigSnapshot 序列化
    test_config_snapshot_roundtrip();
    test_config_snapshot_signing_data_deterministic();

    // 3. ConfigDelta 序列化
    test_config_delta_roundtrip();
    test_config_delta_is_full();

    // 4. 本地配置操作
    test_distributor_set_local_increments_epoch();
    test_distributor_get_local();
    test_distributor_delete_local();
    test_distributor_delete_nonexistent_noop();
    test_distributor_get_snapshot();

    // 5. 签名验证
    test_apply_snapshot_valid_signature();
    test_apply_snapshot_invalid_signature_rejected();
    test_apply_snapshot_wrong_pubkey_rejected();
    test_apply_delta_valid_signature();
    test_apply_delta_invalid_signature_rejected();

    // 6. CRDT LWW 合并
    test_apply_delta_lww_higher_version_wins();
    test_apply_delta_lww_lower_version_skipped();
    test_apply_delta_lww_equal_version_skipped();
    test_apply_delta_deletion();

    // 7. epoch 防回退
    test_apply_snapshot_epoch_rollback_rejected();
    test_apply_delta_epoch_rollback_rejected();
    test_apply_snapshot_equal_epoch_rejected();

    // 8. gossip 传播
    test_build_delta_for_no_cache_returns_nullopt();
    test_build_delta_for_returns_cached_delta();
    test_build_delta_for_target_uptodate_returns_nullopt();
    test_on_config_delta_received_updates_node_epoch();

    // 9. 落后检测
    test_lagging_nodes_empty();
    test_lagging_nodes_detects_behind();
    test_update_node_config_epoch_monotonic();

    // 10. 订阅热更新
    test_subscribe_set_local_notification();
    test_subscribe_apply_delta_notification();
    test_subscribe_delete_notification();
    test_subscribe_prefix_match();
    test_unsubscribe_stops_notifications();
    test_subscribe_empty_prefix_matches_all();

    // 11. 历史回滚
    test_history_size_increases();
    test_rollback_to_restores_config();
    test_rollback_to_nonexistent_returns_false();
    test_history_max_10();

    // 12. 并发安全
    test_concurrent_set_local();

    std::cout << "========================================" << std::endl;
    std::cout << " Total: " << total << ", Failed: " << failed << std::endl;
    std::cout << "========================================" << std::endl;

    return failed == 0 ? 0 : 1;
}
