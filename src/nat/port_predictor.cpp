// port_predictor.cpp — P5-D-1 Symmetric NAT 端口预测引擎实现
//
// 4 模型实现：TwoPoint / LinearRegression / WeightedRecent / Hybrid
// 持久化：行式文本格式（peer_hex|port|epoch_ms）

#include "linoh/nat/port_predictor.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <numeric>
#include <sstream>

namespace linoh::nat {

// ============================================================================
// PortObservation 序列化
// ============================================================================

std::string PortObservation::to_string() const {
    // peer_hex（64 字符）| port | epoch_ms
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < peer_endpoint.size(); ++i) {
        oss << std::setw(2) << static_cast<unsigned>(peer_endpoint.data()[i]);
    }
    auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
                     timestamp.time_since_epoch()).count();
    oss << '|' << std::dec << observed_port << '|' << epoch;
    return oss.str();
}

bool PortObservation::parse(std::string_view line, PortObservation &out) {
    // 格式：peer_hex(64)|port|epoch_ms
    if (line.size() < 66) return false;  // 64 + '|' + 至少 1 port
    // 找两个分隔符
    auto p1 = line.find('|');
    if (p1 == std::string_view::npos || p1 != 64) return false;
    auto p2 = line.find('|', p1 + 1);
    if (p2 == std::string_view::npos) return false;

    std::string_view hex_part = line.substr(0, 64);
    std::string_view port_part = line.substr(p1 + 1, p2 - p1 - 1);
    std::string_view epoch_part = line.substr(p2 + 1);

    // 解析 peer_hex
    if (hex_part.size() != 64) return false;
    for (std::size_t i = 0; i < 32; ++i) {
        auto hex_val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hex_val(hex_part[i * 2]);
        int lo = hex_val(hex_part[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out.peer_endpoint.data()[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }

    // 解析 port
    std::uint32_t port = 0;
    for (char c : port_part) {
        if (c < '0' || c > '9') return false;
        port = port * 10 + (c - '0');
        if (port > 65535) return false;
    }
    if (port_part.empty()) return false;
    out.observed_port = static_cast<std::uint16_t>(port);

    // 解析 epoch_ms
    long long epoch = 0;
    for (char c : epoch_part) {
        if (c < '0' || c > '9') return false;
        epoch = epoch * 10 + (c - '0');
        if (epoch < 0) return false;  // 溢出保护
    }
    if (epoch_part.empty()) return false;
    out.timestamp = PortPredictTimePoint(
        std::chrono::milliseconds(epoch));
    return true;
}

// ============================================================================
// 工具函数
// ============================================================================

LinearFit linear_fit(const std::vector<double> &xs, const std::vector<double> &ys) {
    LinearFit fit;
    std::size_t n = xs.size();
    if (n < 2 || ys.size() != n) return fit;

    double sum_x = std::accumulate(xs.begin(), xs.end(), 0.0);
    double sum_y = std::accumulate(ys.begin(), ys.end(), 0.0);
    double sum_xx = 0.0, sum_xy = 0.0;
    for (std::size_t i = 0; i < n; ++i) {
        sum_xx += xs[i] * xs[i];
        sum_xy += xs[i] * ys[i];
    }
    double denom = n * sum_xx - sum_x * sum_x;
    if (std::abs(denom) < 1e-12) return fit;  // 垂直线，无法拟合

    fit.slope = (n * sum_xy - sum_x * sum_y) / denom;
    fit.intercept = (sum_y - fit.slope * sum_x) / n;

    // 残差标准差
    double residual_sq_sum = 0.0;
    for (std::size_t i = 0; i < n; ++i) {
        double predicted = fit.slope * xs[i] + fit.intercept;
        double residual = ys[i] - predicted;
        residual_sq_sum += residual * residual;
    }
    fit.residual_stddev = std::sqrt(residual_sq_sum / static_cast<double>(n));
    fit.valid = true;
    return fit;
}

std::vector<std::int32_t> compute_port_deltas(
    const std::deque<PortObservation> &obs) {
    std::vector<std::int32_t> deltas;
    if (obs.size() < 2) return deltas;
    deltas.reserve(obs.size() - 1);
    for (std::size_t i = 1; i < obs.size(); ++i) {
        deltas.push_back(static_cast<std::int32_t>(obs[i].observed_port) -
                         static_cast<std::int32_t>(obs[i - 1].observed_port));
    }
    return deltas;
}

DeltaStats compute_delta_stats(const std::vector<std::int32_t> &deltas) {
    DeltaStats stats;
    if (deltas.empty()) return stats;
    double sum = 0.0;
    for (auto d : deltas) sum += static_cast<double>(d);
    stats.mean = sum / static_cast<double>(deltas.size());
    double sq_sum = 0.0;
    for (auto d : deltas) {
        double diff = static_cast<double>(d) - stats.mean;
        sq_sum += diff * diff;
    }
    stats.stddev = std::sqrt(sq_sum / static_cast<double>(deltas.size()));
    stats.valid = true;
    return stats;
}

// ============================================================================
// PortPredictor 生命周期
// ============================================================================

PortPredictor::PortPredictor(PortPredictorConfig config)
    : config_(std::move(config)) {
    if (!config_.persistence_path.empty()) {
        load_from_file(config_.persistence_path);
    }
}

PortPredictor::~PortPredictor() {
    if (!config_.persistence_path.empty()) {
        save_to_file(config_.persistence_path);
    }
}

// ============================================================================
// 内部辅助
// ============================================================================

void PortPredictor::evict_if_needed_(PeerHistory &h) {
    while (h.observations.size() > config_.max_observations_per_peer) {
        h.observations.pop_front();
    }
}

void PortPredictor::maybe_autosave_() {
    // 仅计数标记，不直接 save（写锁内调 save_to_file 会取读锁，锁升级死锁）
    // 实际持久化由析构 + 手动 save_to_file 触发
    if (config_.persistence_path.empty() || config_.autosave_every_observations == 0) {
        return;
    }
    ++autosave_counter_;
}

std::vector<std::uint16_t> PortPredictor::dedup_and_truncate(
    std::vector<std::uint16_t> candidates, std::size_t count) {
    // 去重（保序）
    std::vector<std::uint16_t> result;
    result.reserve(std::min(count, candidates.size()));
    std::unordered_map<std::uint16_t, bool> seen;
    for (auto port : candidates) {
        if (port == 0) continue;  // 0 端口非法
        if (seen[port]) continue;
        seen[port] = true;
        result.push_back(port);
        if (result.size() >= count) break;
    }
    return result;
}

std::size_t PortPredictor::adaptive_count(double confidence, std::size_t requested) const {
    if (requested > 0) return requested;
    // 置信度高→少候选，低→多候选
    // count = min + (1 - confidence) * (max - min)
    double raw = static_cast<double>(config_.min_candidates) +
                 (1.0 - confidence) * static_cast<double>(
                     config_.max_candidates - config_.min_candidates);
    std::size_t c = static_cast<std::size_t>(std::round(raw));
    return (std::max)(config_.min_candidates,
                      (std::min)(config_.max_candidates, c));
}

// ============================================================================
// 观测记录与反馈（写操作）
// ============================================================================

void PortPredictor::record_observation(const base::EndpointId &peer,
                                       std::uint16_t observed_port,
                                       PortPredictTimePoint ts) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto &h = histories_[peer];
    h.observations.emplace_back(peer, observed_port, ts);
    evict_if_needed_(h);
    ++total_observations_;
    maybe_autosave_();
}

void PortPredictor::feedback(const base::EndpointId &peer,
                             std::uint16_t predicted,
                             std::uint16_t actual,
                             bool hit,
                             PortPredictModel model) {
    (void)predicted;  // 当前仅统计命中率，不细化到具体端口
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = histories_.find(peer);
    if (it == histories_.end()) {
        // peer 无历史，仍记录命中统计（创建空历史）
        it = histories_.emplace(peer, PeerHistory{}).first;
    }
    if (hit) {
        ++it->second.hit_stats.hit_count;
        it->second.hit_stats.last_hit_model |= static_cast<std::uint64_t>(1)
                                               << static_cast<int>(model);
    } else {
        ++it->second.hit_stats.miss_count;
    }
}

// ============================================================================
// 预测（读操作）
// ============================================================================

PortPrediction PortPredictor::predict(const base::EndpointId &peer,
                                      std::size_t count) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = histories_.find(peer);
    PortPrediction result;
    if (it == histories_.end() || it->second.observations.empty()) {
        // 冷启动：无历史
        result.observation_count = 0;
        result.confidence = 0.0;
        result.model_used = PortPredictModel::TwoPoint;
        return result;
    }

    const auto &obs = it->second.observations;
    result.observation_count = obs.size();

    if (obs.size() < config_.min_observations_for_advanced) {
        // 观测不足，用 TwoPoint
        result = predict_two_point(obs, count);
    } else {
        // 观测充足，用 Hybrid（融合 Three 模型）
        result = predict_hybrid(obs, count, config_.weighted_decay_tau_sec,
                                it->second.hit_stats);
    }

    // 自适应候选数
    std::size_t actual_count = adaptive_count(result.confidence, count);
    result.candidates = dedup_and_truncate(std::move(result.candidates), actual_count);
    return result;
}

std::size_t PortPredictor::observation_count(const base::EndpointId &peer) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = histories_.find(peer);
    return it == histories_.end() ? 0 : it->second.observations.size();
}

PeerHitStats PortPredictor::hit_stats(const base::EndpointId &peer) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = histories_.find(peer);
    return it == histories_.end() ? PeerHitStats{} : it->second.hit_stats;
}

std::size_t PortPredictor::peer_count() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return histories_.size();
}

std::size_t PortPredictor::total_observations() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return total_observations_;
}

// ============================================================================
// 模型实现
// ============================================================================

PortPrediction PortPredictor::predict_two_point(
    const std::deque<PortObservation> &obs, std::size_t count) {
    PortPrediction result;
    result.model_used = PortPredictModel::TwoPoint;
    result.observation_count = obs.size();
    if (obs.size() < 2) {
        result.confidence = 0.0;
        return result;
    }

    std::uint16_t p1 = obs[obs.size() - 2].observed_port;
    std::uint16_t p2 = obs[obs.size() - 1].observed_port;
    std::int32_t delta = static_cast<std::int32_t>(p2) - static_cast<std::int32_t>(p1);

    std::size_t actual_count = (std::max)(std::size_t{5}, count);
    result.candidates.reserve(actual_count + 2);

    // 主预测：p2 + delta*k
    for (std::size_t k = 1; k <= actual_count; ++k) {
        std::int64_t port = static_cast<std::int64_t>(p2) +
                            static_cast<std::int64_t>(delta) * static_cast<std::int64_t>(k);
        // 端口 wrap 到 [1, 65535]
        port = ((port % 65536) + 65536) % 65536;
        if (port == 0) port = 65535;
        result.candidates.push_back(static_cast<std::uint16_t>(port));
    }
    // fallback：+1, -1 简单增量
    result.candidates.push_back(p2 + 1 == 0 ? 65535 : static_cast<std::uint16_t>(p2 + 1));
    result.candidates.push_back(p2 == 0 ? 65535 : static_cast<std::uint16_t>(p2 - 1));

    // 置信度：基于增量稳定性（多点时看增量方差）
    if (obs.size() >= 3) {
        auto deltas = compute_port_deltas(obs);
        auto stats = compute_delta_stats(deltas);
        if (stats.valid) {
            // stddev 越小置信度越高；stddev=0 → 1.0，stddev>=100 → 0.0
            result.confidence = (std::max)(0.0, 1.0 - stats.stddev / 100.0);
        }
    } else {
        // 仅 2 点，中等置信度
        result.confidence = 0.5;
    }
    return result;
}

PortPrediction PortPredictor::predict_linear_regression(
    const std::deque<PortObservation> &obs, std::size_t count) {
    PortPrediction result;
    result.model_used = PortPredictModel::LinearRegression;
    result.observation_count = obs.size();
    if (obs.size() < 3) {
        // 样本不足，回退 TwoPoint
        return predict_two_point(obs, count);
    }

    // x = 相对秒数（首个观测为 0），y = 端口
    std::vector<double> xs, ys;
    xs.reserve(obs.size());
    ys.reserve(obs.size());
    auto t0 = obs.front().timestamp;
    for (const auto &o : obs) {
        double sec = std::chrono::duration_cast<std::chrono::duration<double>>(
            o.timestamp - t0).count();
        xs.push_back(sec);
        ys.push_back(static_cast<double>(o.observed_port));
    }

    LinearFit fit = linear_fit(xs, ys);
    if (!fit.valid) {
        return predict_two_point(obs, count);
    }

    // 预测下一次：x_next = 最新 x + 平均间隔
    double avg_interval = xs.back() / static_cast<double>(xs.size() - 1);
    double x_next = xs.back() + (std::max)(avg_interval, 1.0);
    double predicted = fit.slope * x_next + fit.intercept;

    std::size_t actual_count = (std::max)(std::size_t{5}, count);
    result.candidates.reserve(actual_count + 4);

    // 主预测 + 附近端口
    auto add_port = [&](double val, int offset) {
        std::int64_t port = static_cast<std::int64_t>(std::round(val)) + offset;
        port = ((port % 65536) + 65536) % 65536;
        if (port == 0) port = 65535;
        result.candidates.push_back(static_cast<std::uint16_t>(port));
    };
    add_port(predicted, 0);
    for (std::size_t k = 1; k <= actual_count; ++k) {
        add_port(predicted, static_cast<int>(k));
        add_port(predicted, -static_cast<int>(k));
    }

    // 置信度：基于残差标准差
    // residual_stddev=0 → 1.0，>=200 → 0.0
    result.confidence = (std::max)(0.0, 1.0 - fit.residual_stddev / 200.0);
    return result;
}

PortPrediction PortPredictor::predict_weighted_recent(
    const std::deque<PortObservation> &obs, std::size_t count,
    double decay_tau_sec) {
    PortPrediction result;
    result.model_used = PortPredictModel::WeightedRecent;
    result.observation_count = obs.size();
    if (obs.size() < 3) {
        return predict_two_point(obs, count);
    }

    auto t_latest = obs.back().timestamp;
    // 加权增量均值
    double weighted_delta_sum = 0.0;
    double weight_sum = 0.0;
    for (std::size_t i = 1; i < obs.size(); ++i) {
        double dt_sec = std::chrono::duration_cast<std::chrono::duration<double>>(
            t_latest - obs[i].timestamp).count();
        double w = std::exp(-dt_sec / decay_tau_sec);
        std::int32_t delta = static_cast<std::int32_t>(obs[i].observed_port) -
                             static_cast<std::int32_t>(obs[i - 1].observed_port);
        weighted_delta_sum += w * static_cast<double>(delta);
        weight_sum += w;
    }
    if (weight_sum < 1e-12) {
        return predict_two_point(obs, count);
    }
    double weighted_delta = weighted_delta_sum / weight_sum;

    std::uint16_t p_latest = obs.back().observed_port;
    std::size_t actual_count = (std::max)(std::size_t{5}, count);
    result.candidates.reserve(actual_count + 2);

    for (std::size_t k = 1; k <= actual_count; ++k) {
        std::int64_t port = static_cast<std::int64_t>(p_latest) +
                            static_cast<std::int64_t>(std::round(weighted_delta * k));
        port = ((port % 65536) + 65536) % 65536;
        if (port == 0) port = 65535;
        result.candidates.push_back(static_cast<std::uint16_t>(port));
    }

    // 置信度：基于权重集中度（最新观测权重占比高→置信度高）
    double latest_dt = std::chrono::duration_cast<std::chrono::duration<double>>(
        t_latest - obs.front().timestamp).count();
    double latest_weight = std::exp(0.0);  // 最新权重=1
    double total_weight_range = std::exp(0.0) - std::exp(-latest_dt / decay_tau_sec);
    result.confidence = (std::max)(0.0, (std::min)(1.0,
        latest_weight / (total_weight_range + 1.0)));
    return result;
}

PortPrediction PortPredictor::predict_hybrid(
    const std::deque<PortObservation> &obs, std::size_t count,
    double decay_tau_sec, const PeerHitStats &stats) {
    PortPrediction result;
    result.model_used = PortPredictModel::Hybrid;
    result.observation_count = obs.size();

    std::size_t actual_count = (std::max)(std::size_t{5}, count);

    // 并行计算三模型
    auto tp = predict_two_point(obs, actual_count);
    auto lr = predict_linear_regression(obs, actual_count);
    auto wr = predict_weighted_recent(obs, actual_count, decay_tau_sec);

    // 模型权重：基于自身置信度 + 历史命中率加成
    double hit_rate = stats.hit_rate();
    double hit_boost = 0.5 + hit_rate;  // [0.5, 1.5]
    double w_tp = tp.confidence * hit_boost;
    double w_lr = lr.confidence * hit_boost;
    double w_wr = wr.confidence * hit_boost;

    // 融合候选：每模型按权重贡献候选，加权排序
    struct ScoredPort {
        std::uint16_t port;
        double score;
    };
    std::unordered_map<std::uint16_t, double> port_scores;

    auto add_model = [&](const PortPrediction &p, double weight) {
        for (std::size_t i = 0; i < p.candidates.size(); ++i) {
            double pos_score = weight * (1.0 / static_cast<double>(i + 1));
            port_scores[p.candidates[i]] += pos_score;
        }
    };
    add_model(tp, w_tp);
    add_model(lr, w_lr);
    add_model(wr, w_wr);

    // 排序取 Top-N
    std::vector<ScoredPort> scored;
    scored.reserve(port_scores.size());
    for (const auto &kv : port_scores) {
        scored.push_back({kv.first, kv.second});
    }
    std::sort(scored.begin(), scored.end(),
              [](const ScoredPort &a, const ScoredPort &b) {
                  return a.score > b.score;
              });

    result.candidates.reserve(actual_count);
    for (std::size_t i = 0; i < scored.size() && i < actual_count; ++i) {
        result.candidates.push_back(scored[i].port);
    }

    // 混合置信度：三模型置信度的加权平均
    double total_weight = w_tp + w_lr + w_wr;
    if (total_weight > 1e-12) {
        result.confidence = (tp.confidence * w_tp + lr.confidence * w_lr +
                             wr.confidence * w_wr) / total_weight;
    } else {
        result.confidence = (tp.confidence + lr.confidence + wr.confidence) / 3.0;
    }
    return result;
}

// ============================================================================
// 持久化
// ============================================================================

bool PortPredictor::save_to_file(const std::string &path) const {
    std::string filepath = path.empty() ? config_.persistence_path : path;
    if (filepath.empty()) return false;

    std::shared_lock<std::shared_mutex> lk(mu_);
    std::ofstream ofs(filepath, std::ios::out | std::ios::trunc);
    if (!ofs.is_open()) return false;

    ofs << "# linoh PortPredictor history (v3.6.0)\n";
    ofs << "# format: peer_hex(64)|port|epoch_ms\n";
    ofs << "# peers: " << histories_.size()
        << " observations: " << total_observations_ << "\n";

    for (const auto &kv : histories_) {
        for (const auto &o : kv.second.observations) {
            ofs << o.to_string() << '\n';
        }
        // 命中统计作为注释行
        if (kv.second.hit_stats.total() > 0) {
            ofs << "# stats " << peer_to_hex_(kv.first)
                << ' ' << kv.second.hit_stats.hit_count
                << ' ' << kv.second.hit_stats.miss_count << '\n';
        }
    }
    return ofs.good();
}

int PortPredictor::load_from_file(const std::string &path) {
    std::string filepath = path.empty() ? config_.persistence_path : path;
    if (filepath.empty()) return -1;

    std::ifstream ifs(filepath);
    if (!ifs.is_open()) return -1;

    std::unique_lock<std::shared_mutex> lk(mu_);
    // P5-D-3 修复：清空现有历史，保证 load 幂等（多次调用不累积重复数据）。
    // 与 NatStats::load_from_file 行为对齐，防御双重加载场景。
    histories_.clear();
    total_observations_ = 0;
    autosave_counter_ = 0;

    int loaded = 0;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty() || line[0] == '#') continue;
        PortObservation obs;
        if (PortObservation::parse(line, obs)) {
            auto &h = histories_[obs.peer_endpoint];
            h.observations.push_back(obs);
            evict_if_needed_(h);
            ++total_observations_;
            ++loaded;
        }
    }
    return loaded;
}

void PortPredictor::clear() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    histories_.clear();
    total_observations_ = 0;
    autosave_counter_ = 0;
}

// ============================================================================
// 私有辅助（peer_hex 转换，持久化 stats 行用）
// ============================================================================

std::string PortPredictor::peer_to_hex_(const base::EndpointId &peer) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < peer.size(); ++i) {
        oss << std::setw(2) << static_cast<unsigned>(peer.data()[i]);
    }
    return oss.str();
}

}  // namespace linoh::nat
