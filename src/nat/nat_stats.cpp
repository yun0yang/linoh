// nat_stats.cpp — P5-D-2 NAT 穿透统计模型实现
//
// 三维统计：(NAT 类型, 运营商, 区域)
// 策略推荐：score = success_rate * 0.7 + sample_confidence * 0.3
// 持久化：行式文本格式（nat_type|carrier|region|strategy|success|duration_ms|timestamp_ms）

#include "linoh/nat/nat_stats.hpp"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <sstream>

namespace linoh::nat {

// ============================================================================
// GeoRegion 解析
// ============================================================================

GeoRegion parse_geo_region(const std::string &s) {
    if (s == "north")      return GeoRegion::North;
    if (s == "south")      return GeoRegion::South;
    if (s == "east")       return GeoRegion::East;
    if (s == "central")    return GeoRegion::Central;
    if (s == "southwest")  return GeoRegion::Southwest;
    if (s == "northwest")  return GeoRegion::Northwest;
    if (s == "northeast")  return GeoRegion::Northeast;
    if (s == "overseas")   return GeoRegion::Overseas;
    return GeoRegion::Unknown;
}

// ============================================================================
// NatType / CgnStrategy 字符串转换（本地工具函数）
// ============================================================================

namespace {

const char *nat_type_name(net::NatType t) {
    switch (t) {
        case net::NatType::OpenInternet:       return "OpenInternet";
        case net::NatType::FullCone:           return "FullCone";
        case net::NatType::RestrictedCone:     return "RestrictedCone";
        case net::NatType::PortRestrictedCone: return "PortRestrictedCone";
        case net::NatType::Symmetric:          return "Symmetric";
        case net::NatType::Unknown:            return "Unknown";
    }
    return "Unknown";
}

bool parse_nat_type(const std::string &s, net::NatType &out) {
    if (s == "OpenInternet")       { out = net::NatType::OpenInternet;       return true; }
    if (s == "FullCone")           { out = net::NatType::FullCone;           return true; }
    if (s == "RestrictedCone")     { out = net::NatType::RestrictedCone;     return true; }
    if (s == "PortRestrictedCone") { out = net::NatType::PortRestrictedCone; return true; }
    if (s == "Symmetric")          { out = net::NatType::Symmetric;          return true; }
    if (s == "Unknown")            { out = net::NatType::Unknown;            return true; }
    return false;
}

bool parse_cgn_strategy(const std::string &s, CgnStrategy &out) {
    if (s == "direct")           { out = CgnStrategy::DirectConnect;   return true; }
    if (s == "standard")         { out = CgnStrategy::StandardRfc5389; return true; }
    if (s == "symmetric")        { out = CgnStrategy::SymmetricNat;    return true; }
    if (s == "relay-fallback")   { out = CgnStrategy::RelayFallback;   return true; }
    if (s == "parallel-try")     { out = CgnStrategy::ParallelTry;     return true; }
    return false;
}

} // anonymous namespace

// ============================================================================
// PenetrationRecord 序列化
// ============================================================================

std::string PenetrationRecord::to_string() const {
    std::ostringstream oss;
    oss << nat_type_name(nat_type)
        << '|' << carrier
        << '|' << geo_region_name(region)
        << '|' << cgn_strategy_name(strategy_used)
        << '|' << (success ? 1 : 0)
        << '|' << duration.count()
        << '|' << timestamp_ms;
    return oss.str();
}

// ============================================================================
// StatsKey 序列化
// ============================================================================

std::string StatsKey::to_string() const {
    std::ostringstream oss;
    oss << nat_type_name(nat_type)
        << '|' << carrier
        << '|' << geo_region_name(region);
    return oss.str();
}

// ============================================================================
// NatStats 实现
// ============================================================================

NatStats::NatStats(NatStatsConfig config)
    : config_(std::move(config)) {
    // P5-D-3 方案 A：构造期自动加载持久化数据（与 PortPredictor 行为对齐）。
    // Endpoint 不再显式 load_from_file，避免双重加载。
    if (!config_.persistence_path.empty()) {
        load_from_file(config_.persistence_path);
    }
}

double NatStats::compute_sample_confidence(std::uint64_t samples) const {
    double ratio = static_cast<double>(samples) /
                   static_cast<double>(config_.sample_saturation_limit);
    return (std::min)(ratio, 1.0);
}

void NatStats::evict_lru_(KeyBucket &bucket) {
    while (bucket.records.size() > config_.max_records_per_key) {
        const auto &old = bucket.records.front();
        // 维护 per_strategy 计数
        auto it = bucket.per_strategy.find(old.strategy_used);
        if (it != bucket.per_strategy.end()) {
            if (it->second.first > 0) --it->second.first;
            if (old.success && it->second.second > 0) --it->second.second;
        }
        bucket.records.pop_front();
    }
}

void NatStats::maybe_autosave_() const {
    // 仅在 autosave_interval > 0 且达到阈值时标记
    // 实际持久化由调用方显式调用 save_to_file 或析构前触发
    // （避免在写锁内调用 save_to_file 导致锁升级死锁）
    // 这里不做实际 I/O，仅计数
}

void NatStats::record(const PenetrationRecord &r) {
    StatsKey key{r.nat_type, r.carrier, r.region};

    std::unique_lock<std::shared_mutex> lk(mu_);
    auto &bucket = buckets_[key];
    bucket.records.push_back(r);
    bucket.total += 1;
    if (r.success) bucket.success += 1;
    bucket.total_duration += r.duration;

    // 更新 per_strategy 统计
    auto &strat_pair = bucket.per_strategy[r.strategy_used];
    strat_pair.first += 1;  // total
    if (r.success) strat_pair.second += 1;  // success

    // LRU 淘汰
    evict_lru_(bucket);

    // 自动保存计数
    if (config_.autosave_interval > 0) {
        unsaved_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

StatsSnapshot NatStats::query(const StatsKey &key) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
        return StatsSnapshot{};
    }
    const auto &bucket = it->second;
    StatsSnapshot snap;
    snap.total = bucket.total;
    snap.success = bucket.success;
    snap.success_rate = (bucket.total > 0)
        ? static_cast<double>(bucket.success) / static_cast<double>(bucket.total)
        : 0.0;
    snap.avg_duration = (bucket.total > 0)
        ? std::chrono::milliseconds(bucket.total_duration.count() /
                                    static_cast<std::int64_t>(bucket.total))
        : std::chrono::milliseconds(0);
    snap.sample_confidence = static_cast<std::uint64_t>(
        compute_sample_confidence(bucket.total) * 100.0);
    return snap;
}

std::vector<StrategyStats> NatStats::query_strategies(const StatsKey &key) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
        return {};
    }
    const auto &bucket = it->second;
    std::vector<StrategyStats> result;
    result.reserve(bucket.per_strategy.size());
    for (const auto &[strat, pair] : bucket.per_strategy) {
        StrategyStats ss;
        ss.strategy = strat;
        ss.total = pair.first;
        ss.success = pair.second;
        ss.success_rate = (pair.first > 0)
            ? static_cast<double>(pair.second) / static_cast<double>(pair.first)
            : 0.0;
        // 注意：per_strategy 未单独追踪 duration，avg_duration 需要遍历 records
        // 为简化实现，这里用 bucket 的 avg_duration 作为近似
        ss.avg_duration = (bucket.total > 0)
            ? std::chrono::milliseconds(bucket.total_duration.count() /
                                        static_cast<std::int64_t>(bucket.total))
            : std::chrono::milliseconds(0);
        result.push_back(ss);
    }
    // 按成功率降序排序
    std::sort(result.begin(), result.end(),
              [](const StrategyStats &a, const StrategyStats &b) {
                  if (a.success_rate != b.success_rate) return a.success_rate > b.success_rate;
                  return a.total > b.total;  // 成功率相同时按样本数降序
              });
    return result;
}

std::optional<std::pair<CgnStrategy, double>>
NatStats::recommend_strategy(const StatsKey &key,
                              std::span<const CgnStrategy> candidates) const {
    if (candidates.empty()) {
        return std::nullopt;
    }

    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = buckets_.find(key);

    // 冷启动：无记录或样本不足，返回 nullopt（调用方回退 CGN 规则）
    if (it == buckets_.end() || it->second.total < config_.cold_start_threshold) {
        return std::nullopt;
    }

    const auto &bucket = it->second;
    double sample_conf = compute_sample_confidence(bucket.total);

    // 遍历候选策略，计算评分
    CgnStrategy best = candidates[0];
    double best_score = -1.0;
    double best_rate = 0.0;

    for (CgnStrategy cand : candidates) {
        auto sit = bucket.per_strategy.find(cand);
        if (sit == bucket.per_strategy.end() || sit->second.first == 0) {
            // 该策略无历史记录，评分 = 0（保守）
            // 但仍可作为候选（可能是新策略）
            double score = 0.0;
            if (score > best_score) {
                best_score = score;
                best = cand;
                best_rate = 0.0;
            }
            continue;
        }
        double rate = static_cast<double>(sit->second.second) /
                      static_cast<double>(sit->second.first);
        double score = rate * config_.weight_success_rate +
                       sample_conf * config_.weight_sample_confidence;
        if (score > best_score) {
            best_score = score;
            best = cand;
            best_rate = rate;
        }
    }

    return std::make_pair(best, best_rate);
}

double NatStats::global_success_rate() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::uint64_t total = 0, success = 0;
    for (const auto &[key, bucket] : buckets_) {
        total += bucket.total;
        success += bucket.success;
    }
    return (total > 0) ? static_cast<double>(success) / static_cast<double>(total) : 0.0;
}

std::size_t NatStats::key_count() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return buckets_.size();
}

std::uint64_t NatStats::total_records() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::uint64_t total = 0;
    for (const auto &[key, bucket] : buckets_) {
        total += bucket.total;
    }
    return total;
}

// ============================================================================
// 持久化
// ============================================================================

bool NatStats::save_to_file(const std::string &path) const {
    std::string filepath = path.empty() ? config_.persistence_path : path;
    if (filepath.empty()) {
        return false;
    }

    std::shared_lock<std::shared_mutex> lk(mu_);
    std::ofstream ofs(filepath, std::ios::out | std::ios::trunc);
    if (!ofs.is_open()) {
        return false;
    }

    // 文件头
    ofs << "# linoh nat_stats v1\n";
    ofs << "# format: nat_type|carrier|region|strategy|success|duration_ms|timestamp_ms\n";

    // 写入所有记录
    for (const auto &[key, bucket] : buckets_) {
        for (const auto &r : bucket.records) {
            ofs << r.to_string() << '\n';
        }
    }

    ofs.flush();
    unsaved_count_.store(0, std::memory_order_relaxed);
    return ofs.good();
}

int NatStats::load_from_file(const std::string &path) {
    std::string filepath = path.empty() ? config_.persistence_path : path;
    if (filepath.empty()) {
        return -1;
    }

    std::ifstream ifs(filepath);
    if (!ifs.is_open()) {
        return -1;
    }

    std::unique_lock<std::shared_mutex> lk(mu_);
    buckets_.clear();

    int loaded = 0;
    std::string line;
    while (std::getline(ifs, line)) {
        // 跳过注释和空行
        if (line.empty() || line[0] == '#') continue;

        // 解析：nat_type|carrier|region|strategy|success|duration_ms|timestamp_ms
        PenetrationRecord r;
        std::istringstream iss(line);
        std::string nat_str, carrier, region_str, strat_str, success_str, dur_str, ts_str;

        if (!std::getline(iss, nat_str, '|')) continue;
        if (!std::getline(iss, carrier, '|')) continue;
        if (!std::getline(iss, region_str, '|')) continue;
        if (!std::getline(iss, strat_str, '|')) continue;
        if (!std::getline(iss, success_str, '|')) continue;
        if (!std::getline(iss, dur_str, '|')) continue;
        if (!std::getline(iss, ts_str)) continue;

        if (!parse_nat_type(nat_str, r.nat_type)) continue;
        r.carrier = carrier;
        r.region = parse_geo_region(region_str);
        if (!parse_cgn_strategy(strat_str, r.strategy_used)) continue;

        // success
        if (success_str == "1") r.success = true;
        else if (success_str == "0") r.success = false;
        else continue;

        // duration_ms
        try {
            r.duration = std::chrono::milliseconds(std::stoll(dur_str));
        } catch (...) { continue; }

        // timestamp_ms
        try {
            r.timestamp_ms = std::stoll(ts_str);
        } catch (...) { continue; }

        // 写入 bucket
        StatsKey key{r.nat_type, r.carrier, r.region};
        auto &bucket = buckets_[key];
        bucket.records.push_back(r);
        bucket.total += 1;
        if (r.success) bucket.success += 1;
        bucket.total_duration += r.duration;
        auto &strat_pair = bucket.per_strategy[r.strategy_used];
        strat_pair.first += 1;
        if (r.success) strat_pair.second += 1;

        ++loaded;
    }

    return loaded;
}

void NatStats::clear() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    buckets_.clear();
    unsaved_count_.store(0, std::memory_order_relaxed);
}

// ============================================================================
// 默认候选策略列表
// ============================================================================

std::vector<CgnStrategy> default_candidates(net::NatType nat_type) {
    switch (nat_type) {
        case net::NatType::OpenInternet:
            // 公网直连，无需打洞
            return {CgnStrategy::DirectConnect, CgnStrategy::StandardRfc5389};
        case net::NatType::FullCone:
        case net::NatType::RestrictedCone:
        case net::NatType::PortRestrictedCone:
            // Cone NAT：标准 STUN 打洞成功率高
            return {CgnStrategy::StandardRfc5389, CgnStrategy::SymmetricNat,
                    CgnStrategy::RelayFallback};
        case net::NatType::Symmetric:
            // 对称 NAT：端口预测 + 并行尝试 + Relay 兜底
            return {CgnStrategy::SymmetricNat, CgnStrategy::ParallelTry,
                    CgnStrategy::RelayFallback};
        case net::NatType::Unknown:
            // 未知：全策略候选，由统计模型排序
            return {CgnStrategy::StandardRfc5389, CgnStrategy::SymmetricNat,
                    CgnStrategy::ParallelTry, CgnStrategy::RelayFallback};
    }
    return {CgnStrategy::RelayFallback};
}

} // namespace linoh::nat
