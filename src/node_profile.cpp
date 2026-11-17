// node_profile.cpp — NodeProfile 评分实现 + Store 线程安全 + 文本持久化
//
// 评分归一化基准（消费级显卡场景，以 RTX 4090 为算力天花板）：
//   - compute: 以 RTX 4090 (FP16~165 TFLOPS, VRAM 24GB) 为 1.0 基准
//   - network: 1Gbps 上行 + 5ms RTT + 0% 丢包 为 1.0 基准
//   - stability: 直接使用 [0,1] score
//   - geo: 已知区域 1.0，Unknown 0.3（鼓励节点上报地理信息）

#include "linoh/node_profile.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace linoh {

// ============================================================================
// ComputeCap::normalized_score
// 算力归一化：取 FP16/INT4/VRAM 三项的加权几何平均，以 RTX 4090 为基准
// ============================================================================

float NodeProfile::ComputeCap::normalized_score() const noexcept {
    // 基准：RTX 4090 — FP16 165 TFLOPS, INT4 660 TFLOPS, VRAM 24576 MB
    constexpr float kRefFp16 = 165.0f;
    constexpr float kRefInt4 = 660.0f;
    constexpr float kRefVram = 24576.0f;

    // 防止除零
    if (kRefFp16 <= 0.0f || kRefInt4 <= 0.0f || kRefVram <= 0.0f) return 0.0f;

    // 各项归一化并裁剪到 [0,1]
    float fp16_norm = (tflops_fp16 > 0.0f) ? std::min(tflops_fp16 / kRefFp16, 1.0f) : 0.0f;
    float int4_norm = (tflops_int4 > 0.0f) ? std::min(tflops_int4 / kRefInt4, 1.0f) : 0.0f;
    float vram_norm = (vram_mb > 0) ? std::min(static_cast<float>(vram_mb) / kRefVram, 1.0f) : 0.0f;

    // 加权：FP16 0.45 + INT4 0.35 + VRAM 0.20（PP/DP 偏 FP16，EP 偏 INT4）
    // 若某项为 0（未探测），仅以其余项归一化
    float weight_sum = 0.0f;
    float score = 0.0f;
    if (fp16_norm > 0.0f) { score += 0.45f * fp16_norm; weight_sum += 0.45f; }
    if (int4_norm > 0.0f) { score += 0.35f * int4_norm; weight_sum += 0.35f; }
    if (vram_norm > 0.0f) { score += 0.20f * vram_norm; weight_sum += 0.20f; }

    if (weight_sum <= 0.0f) return 0.0f;
    return score / weight_sum;
}

// ============================================================================
// NetworkCap::normalized_score
// 网络归一化：带宽 + RTT + 丢包 综合分
// ============================================================================

float NodeProfile::NetworkCap::normalized_score() const noexcept {
    // 基准：1 Gbps = 1,000,000,000 bps
    constexpr float kRefBps = 1'000'000'000.0f;
    // 基准 RTT：5ms（同城），上限 200ms
    constexpr float kRefRtt = 5.0f;
    constexpr float kMaxRtt = 200.0f;

    // 带宽分（取上下行较小者，瓶颈决定）
    float bw_bps = static_cast<float>(std::min(uplink_bps, downlink_bps));
    float bw_norm = (bw_bps > 0.0f) ? std::min(bw_bps / kRefBps, 1.0f) : 0.0f;

    // RTT 分（越低越好，5ms=1.0，200ms=0.0）
    float rtt_norm = 0.0f;
    if (rtt_ms_avg > 0) {
        float r = static_cast<float>(rtt_ms_avg);
        if (r <= kRefRtt) rtt_norm = 1.0f;
        else if (r >= kMaxRtt) rtt_norm = 0.0f;
        else rtt_norm = (kMaxRtt - r) / (kMaxRtt - kRefRtt);
    }

    // 丢包分（0%=1.0，5%=0.0）
    float loss_norm = 1.0f;
    if (loss_rate < 0.0f) loss_norm = 1.0f;
    else if (loss_rate > 0.05f) loss_norm = 0.0f;
    else loss_norm = 1.0f - (loss_rate / 0.05f);

    // 网络分级惩罚：Hard *0.5，Wan *0.8，Lan *1.0
    float class_mult = 1.0f;
    switch (net_class) {
        case NetClass::Lan:  class_mult = 1.0f;  break;
        case NetClass::Wan:  class_mult = 0.8f;  break;
        case NetClass::Hard: class_mult = 0.5f;  break;
    }

    // 加权：带宽 0.5 + RTT 0.3 + 丢包 0.2，再乘分级系数
    float raw = 0.5f * bw_norm + 0.3f * rtt_norm + 0.2f * loss_norm;
    return std::min(raw * class_mult, 1.0f);
}

// ============================================================================
// StabilityCap::compute_score
// 稳定性评分公式
// ============================================================================

float NodeProfile::StabilityCap::compute_score(
    std::uint32_t uptime_seconds,
    std::uint32_t disconnect_count,
    float task_success_rate) noexcept {

    // 维度 1：断连惩罚（24h 内 0 次=1.0，24 次=0.0）
    float disc_ratio = (disconnect_count >= 24) ? 1.0f
                                                : static_cast<float>(disconnect_count) / 24.0f;
    float disc_score = 1.0f - disc_ratio;

    // 维度 2：任务成功率（直接使用，裁剪到 [0,1]）
    float tsr = (task_success_rate < 0.0f) ? 0.0f
              : (task_success_rate > 1.0f) ? 1.0f
              : task_success_rate;

    // 维度 3：在线时长（满 24h=1.0）
    constexpr float kFullDay = 86400.0f;
    float uptime_ratio = static_cast<float>(uptime_seconds) / kFullDay;
    if (uptime_ratio > 1.0f) uptime_ratio = 1.0f;

    // 加权：0.4*断连 + 0.3*成功率 + 0.3*在线时长
    float s = 0.4f * disc_score + 0.3f * tsr + 0.3f * uptime_ratio;

    // 裁剪到 [0,1]
    if (s < 0.0f) s = 0.0f;
    if (s > 1.0f) s = 1.0f;
    return s;
}

void NodeProfile::StabilityCap::refresh_score() noexcept {
    score = compute_score(uptime_seconds, disconnect_count, task_success_rate);
    last_updated = std::chrono::system_clock::now();
}

// ============================================================================
// GeoCap::normalized_score
// ============================================================================

float NodeProfile::GeoCap::normalized_score() const noexcept {
    // 已知具体区域：1.0
    // Unknown：0.3（鼓励节点上报地理信息，但不完全惩罚）
    // Backbone：1.0（骨干节点定位明确）
    if (region == GeoRegion::Unknown) return 0.3f;
    return 1.0f;
}

// ============================================================================
// NodeProfile::overall_score
// ============================================================================

float NodeProfile::overall_score() const noexcept {
    return overall_score(NodeScoreWeights{});
}

float NodeProfile::overall_score(const NodeScoreWeights &w) const noexcept {
    float s = 0.0f;
    s += w.weight_compute   * compute.normalized_score();
    s += w.weight_network   * network.normalized_score();
    s += w.weight_stability * stability.score;
    s += w.weight_geo       * geo.normalized_score();

    // 权重归一化（防止用户配置权重总和 != 1.0）
    float wsum = w.weight_compute + w.weight_network + w.weight_stability + w.weight_geo;
    if (wsum <= 0.0f) return 0.0f;

    float result = s / wsum;
    if (result < 0.0f) result = 0.0f;
    if (result > 1.0f) result = 1.0f;
    return result;
}

// ============================================================================
// NodeProfile::brief
// ============================================================================

std::string NodeProfile::brief() const {
    char buf[256];
    std::snprintf(buf, sizeof(buf),
        "NodeProfile{%s, gpu=%s vram=%uMB fp16=%.1fT, "
        "up=%uMbps rtt=%ums loss=%.3f net=%s, "
        "stab=%.3f(up=%us disc=%u tsr=%.2f), "
        "geo=%s/%s, overall=%.3f}",
        node_id.empty() ? "-" : node_id.c_str(),
        compute.gpu_model.empty() ? "-" : compute.gpu_model.c_str(),
        compute.vram_mb,
        compute.tflops_fp16,
        network.uplink_bps / 1'000'000,
        network.rtt_ms_avg,
        network.loss_rate,
        net_class_name(network.net_class),
        stability.score,
        stability.uptime_seconds,
        stability.disconnect_count,
        stability.task_success_rate,
        geo_region_name(geo.region),
        geo.city.empty() ? "-" : geo.city.c_str(),
        overall_score());
    return std::string(buf);
}

// ============================================================================
// NodeProfileStore — 线程安全存储
// ============================================================================

void NodeProfileStore::upsert(const NodeProfile &profile) {
    std::lock_guard<std::mutex> lk(mu_);
    profiles_[profile.endpoint_id] = profile;
}

std::optional<NodeProfile> NodeProfileStore::get(const base::EndpointId &id) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = profiles_.find(id);
    if (it == profiles_.end()) return std::nullopt;
    return it->second;
}

bool NodeProfileStore::erase(const base::EndpointId &id) {
    std::lock_guard<std::mutex> lk(mu_);
    return profiles_.erase(id) > 0;
}

std::size_t NodeProfileStore::size() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return profiles_.size();
}

void NodeProfileStore::clear() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    profiles_.clear();
}

std::vector<NodeProfile> NodeProfileStore::snapshot() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<NodeProfile> out;
    out.reserve(profiles_.size());
    for (const auto &kv : profiles_) out.push_back(kv.second);
    return out;
}

std::vector<NodeProfile> NodeProfileStore::top_n(
    std::size_t n, const NodeScoreWeights &w) const {
    std::lock_guard<std::mutex> lk(mu_);
    if (n == 0 || profiles_.empty()) return {};

    // 拷贝到 vector 并按 overall_score 降序排序
    std::vector<NodeProfile> out;
    out.reserve(profiles_.size());
    for (const auto &kv : profiles_) out.push_back(kv.second);

    std::sort(out.begin(), out.end(),
        [&w](const NodeProfile &a, const NodeProfile &b) {
            return a.overall_score(w) > b.overall_score(w);
        });

    if (out.size() > n) out.resize(n);
    return out;
}

// ============================================================================
// 文本持久化（INI 风格）
// ============================================================================
//
// 文件格式示例：
//   # linoh node profile cache v1
//   count=2
//
//   [node]
//   endpoint_id=abcd1234...
//   node_id=gpu2-master
//   gpu_model=RTX 4090
//   vram_mb=24576
//   tflops_fp16=165.0
//   tflops_int4=660.0
//   cuda_cores=16384
//   uplink_bps=1000000000
//   downlink_bps=1000000000
//   rtt_ms_avg=5
//   rtt_ms_p99=12
//   loss_rate=0.001
//   net_class=lan
//   stability_score=0.950
//   uptime_seconds=86400
//   disconnect_count=1
//   task_success_rate=0.98
//   geo_region=north
//   city=Beijing
//   isp=ChinaUnicom
//
//   [node]
//   ...

namespace {

/// EndpointId <-> hex 字符串互转（持久化用）
std::string endpoint_id_to_hex(const base::EndpointId &id) {
    static const char *kHex = "0123456789abcdef";
    std::string s;
    s.reserve(id.size() * 2);
    const uint8_t *p = id.data();
    for (std::size_t i = 0; i < id.size(); ++i) {
        s.push_back(kHex[(p[i] >> 4) & 0x0F]);
        s.push_back(kHex[p[i] & 0x0F]);
    }
    return s;
}

bool hex_to_endpoint_id(const std::string &hex, base::EndpointId &out) {
    if (hex.size() != base::EndpointId::kSize * 2) return false;
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::array<uint8_t, base::EndpointId::kSize> bytes{};
    for (std::size_t i = 0; i < base::EndpointId::kSize; ++i) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    out = base::EndpointId::from_bytes(bytes);
    return true;
}

/// 去除行首尾空白
std::string trim(const std::string &s) {
    std::size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

/// 解析 key=value 行（返回是否成功）
bool parse_kv(const std::string &line, std::string &key, std::string &val) {
    auto eq = line.find('=');
    if (eq == std::string::npos) return false;
    key = trim(line.substr(0, eq));
    val = trim(line.substr(eq + 1));
    return !key.empty();
}

}  // namespace

bool NodeProfileStore::save_to_file(const std::string &path) const {
    std::lock_guard<std::mutex> lk(mu_);

    std::ofstream ofs(path, std::ios::out | std::ios::trunc);
    if (!ofs.is_open()) return false;

    ofs << "# linoh node profile cache v1\n";
    ofs << "count=" << profiles_.size() << "\n\n";

    for (const auto &kv : profiles_) {
        const NodeProfile &p = kv.second;
        ofs << "[node]\n";
        ofs << "endpoint_id=" << endpoint_id_to_hex(p.endpoint_id) << "\n";
        ofs << "node_id=" << p.node_id << "\n";

        // compute
        ofs << "gpu_model=" << p.compute.gpu_model << "\n";
        ofs << "vram_mb=" << p.compute.vram_mb << "\n";
        ofs << "tflops_fp16=" << p.compute.tflops_fp16 << "\n";
        ofs << "tflops_int4=" << p.compute.tflops_int4 << "\n";
        ofs << "cuda_cores=" << p.compute.cuda_cores << "\n";

        // network
        ofs << "uplink_bps=" << p.network.uplink_bps << "\n";
        ofs << "downlink_bps=" << p.network.downlink_bps << "\n";
        ofs << "rtt_ms_avg=" << p.network.rtt_ms_avg << "\n";
        ofs << "rtt_ms_p99=" << p.network.rtt_ms_p99 << "\n";
        ofs << "loss_rate=" << p.network.loss_rate << "\n";
        ofs << "net_class=" << net_class_name(p.network.net_class) << "\n";

        // stability
        ofs << "stability_score=" << p.stability.score << "\n";
        ofs << "uptime_seconds=" << p.stability.uptime_seconds << "\n";
        ofs << "disconnect_count=" << p.stability.disconnect_count << "\n";
        ofs << "task_success_rate=" << p.stability.task_success_rate << "\n";

        // geo
        ofs << "geo_region=" << geo_region_name(p.geo.region) << "\n";
        ofs << "city=" << p.geo.city << "\n";
        ofs << "isp=" << p.geo.isp << "\n";
        ofs << "\n";
    }

    return ofs.good();
}

bool NodeProfileStore::load_from_file(const std::string &path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return false;

    std::vector<NodeProfile> loaded;

    std::string line;
    NodeProfile cur;
    bool in_node = false;

    auto flush = [&]() {
        if (in_node) {
            // 加载完成后刷新稳定性分（防止文件中 score 过期）
            cur.stability.refresh_score();
            loaded.push_back(cur);
            cur = NodeProfile{};
            in_node = false;
        }
    };

    while (std::getline(ifs, line)) {
        std::string t = trim(line);
        if (t.empty()) continue;
        if (t[0] == '#') continue;  // 注释

        if (t == "[node]") {
            flush();
            in_node = true;
            continue;
        }

        if (in_node) {
            std::string key, val;
            if (!parse_kv(t, key, val)) continue;

            if (key == "endpoint_id") {
                base::EndpointId id;
                if (!hex_to_endpoint_id(val, id)) continue;
                cur.endpoint_id = id;
            } else if (key == "node_id") {
                cur.node_id = val;
            } else if (key == "gpu_model") {
                cur.compute.gpu_model = val;
            } else if (key == "vram_mb") {
                cur.compute.vram_mb = static_cast<std::uint32_t>(std::stoul(val));
            } else if (key == "tflops_fp16") {
                cur.compute.tflops_fp16 = std::stof(val);
            } else if (key == "tflops_int4") {
                cur.compute.tflops_int4 = std::stof(val);
            } else if (key == "cuda_cores") {
                cur.compute.cuda_cores = static_cast<std::uint32_t>(std::stoul(val));
            } else if (key == "uplink_bps") {
                cur.network.uplink_bps = static_cast<std::uint32_t>(std::stoul(val));
            } else if (key == "downlink_bps") {
                cur.network.downlink_bps = static_cast<std::uint32_t>(std::stoul(val));
            } else if (key == "rtt_ms_avg") {
                cur.network.rtt_ms_avg = static_cast<std::uint32_t>(std::stoul(val));
            } else if (key == "rtt_ms_p99") {
                cur.network.rtt_ms_p99 = static_cast<std::uint32_t>(std::stoul(val));
            } else if (key == "loss_rate") {
                cur.network.loss_rate = std::stof(val);
            } else if (key == "net_class") {
                cur.network.net_class = net_class_from_name(val);
            } else if (key == "stability_score") {
                cur.stability.score = std::stof(val);
            } else if (key == "uptime_seconds") {
                cur.stability.uptime_seconds = static_cast<std::uint32_t>(std::stoul(val));
            } else if (key == "disconnect_count") {
                cur.stability.disconnect_count = static_cast<std::uint32_t>(std::stoul(val));
            } else if (key == "task_success_rate") {
                cur.stability.task_success_rate = std::stof(val);
            } else if (key == "geo_region") {
                cur.geo.region = geo_region_from_name(val);
            } else if (key == "city") {
                cur.geo.city = val;
            } else if (key == "isp") {
                cur.geo.isp = val;
            }
            // 未知键忽略（向前兼容）
        }
        // 文件头的 count= 字段忽略（以实际 [node] 段数为准）
    }
    flush();

    std::lock_guard<std::mutex> lk(mu_);
    profiles_.clear();
    for (auto &p : loaded) {
        profiles_[p.endpoint_id] = std::move(p);
    }
    return true;
}

}  // namespace linoh
