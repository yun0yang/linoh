// server_config.cpp — NAT 阈值远端下发实现（NAT 穿透优化 P2-G6）

#include "linoh/nat/server_config.hpp"

#include "linoh/util/logging.hpp"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace linoh::nat {

// ============================================================================
// 手写 JSON 解析器（无第三方依赖）
// ============================================================================
//
// 简单递归下降解析器，仅支持本场景所需子集：
//   - 对象 { "key": value, ... }
//   - 字符串 "..."（本场景字段均为标量，字符串值解析后按需匹配）
//   - 数字（整数 / 浮点）
//   - 布尔 true / false
//   - null
//   - 数组 [...]（跳过，本场景不用）
//
// 所有解析失败安全跳过（不抛异常不崩溃），保证容错。

namespace {

class JsonParser {
public:
    explicit JsonParser(std::string_view s) : s_(s), pos_(0) {}

    /// 解析顶层对象，对每个 key 调用 cb(key, value_type, value_str)
    /// value_type: "string" / "number" / "bool" / "null"
    /// value_str: 原始字符串表示（bool 为 "true"/"false"，null 为 "null"）
    bool parse_object(const std::function<void(
        std::string_view key,
        std::string_view value_type,
        std::string_view value_str)> &cb) {
        if (!skip_ws_expect('{')) return false;
        skip_ws();
        if (peek() == '}') { advance(); return true; }  // 空对象 {}
        for (;;) {
            skip_ws();
            std::string_view key;
            if (!parse_string(key)) return false;
            skip_ws();
            if (!skip_ws_expect(':')) return false;
            skip_ws();
            std::string_view vtype, vstr;
            if (!parse_value(vtype, vstr)) return false;
            cb(key, vtype, vstr);
            skip_ws();
            char c = peek();
            if (c == ',') { advance(); continue; }
            if (c == '}') { advance(); return true; }
            return false;  // 非法字符
        }
    }

private:
    std::string_view s_;
    std::size_t pos_;

    char peek() const { return pos_ < s_.size() ? s_[pos_] : '\0'; }
    void advance() { if (pos_ < s_.size()) ++pos_; }
    bool skip_ws() {
        while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' ||
               s_[pos_] == '\n' || s_[pos_] == '\r')) ++pos_;
        return true;
    }
    bool skip_ws_expect(char c) {
        skip_ws();
        if (peek() == c) { advance(); return true; }
        return false;
    }

    bool parse_string(std::string_view &out) {
        if (peek() != '"') return false;
        advance();
        std::size_t start = pos_;
        while (pos_ < s_.size() && s_[pos_] != '"') {
            if (s_[pos_] == '\\' && pos_ + 1 < s_.size()) pos_ += 2;
            else ++pos_;
        }
        if (pos_ >= s_.size()) return false;  // 未闭合
        out = s_.substr(start, pos_ - start);
        advance();  // 跳过闭合 "
        return true;
    }

    bool parse_value(std::string_view &vtype, std::string_view &vstr) {
        char c = peek();
        if (c == '"') {
            std::string_view s;
            if (!parse_string(s)) return false;
            vtype = "string";
            vstr = s;
            return true;
        }
        if (c == 't' || c == 'f') {
            return parse_literal(vtype, vstr);
        }
        if (c == 'n') {
            return parse_literal(vtype, vstr);
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            return parse_number(vtype, vstr);
        }
        if (c == '[') {
            return parse_array(vtype, vstr);
        }
        if (c == '{') {
            return parse_nested_object(vtype, vstr);
        }
        return false;
    }

    bool parse_literal(std::string_view &vtype, std::string_view &vstr) {
        std::size_t start = pos_;
        while (pos_ < s_.size() && (isalnum(static_cast<unsigned char>(s_[pos_])))) ++pos_;
        vstr = s_.substr(start, pos_ - start);
        if (vstr == "true" || vstr == "false") { vtype = "bool"; return true; }
        if (vstr == "null") { vtype = "null"; return true; }
        return false;
    }

    bool parse_number(std::string_view &vtype, std::string_view &vstr) {
        std::size_t start = pos_;
        if (peek() == '-') advance();
        bool has_dot = false;
        while (pos_ < s_.size()) {
            char c = s_[pos_];
            if (c >= '0' && c <= '9') { ++pos_; continue; }
            if (c == '.' && !has_dot) { has_dot = true; ++pos_; continue; }
            if (c == 'e' || c == 'E') {
                ++pos_;
                if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
                continue;
            }
            break;
        }
        vstr = s_.substr(start, pos_ - start);
        vtype = "number";
        return true;
    }

    bool parse_array(std::string_view &vtype, std::string_view &vstr) {
        std::size_t start = pos_;
        advance();  // [
        int depth = 1;
        while (pos_ < s_.size() && depth > 0) {
            char c = s_[pos_];
            if (c == '[') ++depth;
            else if (c == ']') --depth;
            else if (c == '"') {  // 跳过字符串内容
                advance();
                while (pos_ < s_.size() && s_[pos_] != '"') {
                    if (s_[pos_] == '\\' && pos_ + 1 < s_.size()) pos_ += 2;
                    else ++pos_;
                }
            }
            if (depth > 0) advance();
        }
        vstr = s_.substr(start, pos_ - start);
        vtype = "array";
        return true;
    }

    bool parse_nested_object(std::string_view &vtype, std::string_view &vstr) {
        std::size_t start = pos_;
        advance();  // {
        int depth = 1;
        while (pos_ < s_.size() && depth > 0) {
            char c = s_[pos_];
            if (c == '{') ++depth;
            else if (c == '}') --depth;
            else if (c == '"') {
                advance();
                while (pos_ < s_.size() && s_[pos_] != '"') {
                    if (s_[pos_] == '\\' && pos_ + 1 < s_.size()) pos_ += 2;
                    else ++pos_;
                }
            }
            if (depth > 0) advance();
        }
        vstr = s_.substr(start, pos_ - start);
        vtype = "object";
        return true;
    }
};

/// 辅助：从 value_str 解析 double
bool to_double(std::string_view s, double &out) {
    try {
        std::string tmp(s);
        size_t idx = 0;
        double v = std::stod(tmp, &idx);
        if (idx != tmp.size()) return false;
        out = v;
        return true;
    } catch (...) { return false; }
}

/// 辅助：从 value_str 解析 uint32
bool to_uint32(std::string_view s, std::uint32_t &out) {
    try {
        std::string tmp(s);
        size_t idx = 0;
        unsigned long v = std::stoul(tmp, &idx);
        if (idx != tmp.size()) return false;
        out = static_cast<std::uint32_t>(v);
        return true;
    } catch (...) { return false; }
}

/// 辅助：从 value_str 解析 size_t
bool to_size(std::string_view s, std::size_t &out) {
    try {
        std::string tmp(s);
        size_t idx = 0;
        unsigned long long v = std::stoull(tmp, &idx);
        if (idx != tmp.size()) return false;
        out = static_cast<std::size_t>(v);
        return true;
    } catch (...) { return false; }
}

/// 辅助：从 value_str 解析 bool
bool to_bool(std::string_view s, bool &out) {
    if (s == "true") { out = true; return true; }
    if (s == "false") { out = false; return true; }
    return false;
}

/// 辅助：从 value_str 解析 int64（毫秒数）
bool to_int64(std::string_view s, long long &out) {
    try {
        std::string tmp(s);
        size_t idx = 0;
        long long v = std::stoll(tmp, &idx);
        if (idx != tmp.size()) return false;
        out = v;
        return true;
    } catch (...) { return false; }
}

} // anonymous namespace

// ============================================================================
// NatServerConfig 实现
// ============================================================================

NatServerConfig NatServerConfig::from_json(std::string_view json) {
    NatServerConfig cfg;
    JsonParser p(json);
    bool ok = p.parse_object([&](std::string_view key,
                                  std::string_view vtype,
                                  std::string_view vstr) {
        // 打洞/Relay 切换阈值
        if (key == "relay_switch_threshold" && vtype == "number") {
            double v; if (to_double(vstr, v)) cfg.relay_switch_threshold = v;
        } else if (key == "p2p_to_relay_switch_threshold" && vtype == "number") {
            double v; if (to_double(vstr, v)) cfg.p2p_to_relay_switch_threshold = v;
        } else if (key == "relay_to_p2p_switch_threshold" && vtype == "number") {
            double v; if (to_double(vstr, v)) cfg.relay_to_p2p_switch_threshold = v;
        } else if (key == "reconnecting_state_timeout_ms" && vtype == "number") {
            long long v; if (to_int64(vstr, v))
                cfg.reconnecting_state_timeout = std::chrono::milliseconds(v);
        }
        // G1 UDP 探测阈值
        else if (key == "udp_probe_count" && vtype == "number") {
            std::uint32_t v; if (to_uint32(vstr, v)) cfg.udp_probe_count = v;
        } else if (key == "udp_available_threshold" && vtype == "number") {
            double v; if (to_double(vstr, v)) cfg.udp_available_threshold = v;
        } else if (key == "udp_bad_threshold" && vtype == "number") {
            double v; if (to_double(vstr, v)) cfg.udp_bad_threshold = v;
        } else if (key == "udp_probe_recv_timeout_ms" && vtype == "number") {
            long long v; if (to_int64(vstr, v))
                cfg.udp_probe_recv_timeout = std::chrono::milliseconds(v);
        }
        // G2 TCP 兜底策略
        else if (key == "enable_fec_on_bad" && vtype == "bool") {
            bool v; if (to_bool(vstr, v)) cfg.enable_fec_on_bad = v;
        } else if (key == "tcp_connect_timeout_ms" && vtype == "number") {
            long long v; if (to_int64(vstr, v))
                cfg.tcp_connect_timeout = std::chrono::milliseconds(v);
        } else if (key == "skip_udp_probe" && vtype == "bool") {
            bool v; if (to_bool(vstr, v)) cfg.skip_udp_probe = v;
        }
        // CGN 检测阈值
        else if (key == "cgn_port_dispersion_threshold" && vtype == "number") {
            double v; if (to_double(vstr, v)) cfg.cgn_port_dispersion_threshold = v;
        } else if (key == "cgn_confidence_threshold" && vtype == "number") {
            double v; if (to_double(vstr, v)) cfg.cgn_confidence_threshold = v;
        }
        // 端口预测候选数
        else if (key == "port_predict_min_candidates" && vtype == "number") {
            std::size_t v; if (to_size(vstr, v)) cfg.port_predict_min_candidates = v;
        } else if (key == "port_predict_max_candidates" && vtype == "number") {
            std::size_t v; if (to_size(vstr, v)) cfg.port_predict_max_candidates = v;
        }
        // ICE 优化开关
        else if (key == "ice_presume_writable_when_fully_relayed" && vtype == "bool") {
            bool v; if (to_bool(vstr, v)) cfg.ice_presume_writable_when_fully_relayed = v;
        } else if (key == "ice_skip_relay_to_non_relay" && vtype == "bool") {
            bool v; if (to_bool(vstr, v)) cfg.ice_skip_relay_to_non_relay = v;
        } else if (key == "ice_gather_continually" && vtype == "bool") {
            bool v; if (to_bool(vstr, v)) cfg.ice_gather_continually = v;
        } else if (key == "ice_prioritize_most_likely_pairs" && vtype == "bool") {
            bool v; if (to_bool(vstr, v)) cfg.ice_prioritize_most_likely_pairs = v;
        }
        // 未知字段忽略（容错）
    });
    if (!ok) {
        LINOH_WARN("ServerConfig: JSON parse failed, returning empty config");
    }
    return cfg;
}

std::string NatServerConfig::to_json() const {
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    auto emit_d = [&](const char *name, const std::optional<double> &v) {
        if (v) { if (!first) oss << ","; oss << "\"" << name << "\":" << *v; first = false; }
    };
    auto emit_b = [&](const char *name, const std::optional<bool> &v) {
        if (v) { if (!first) oss << ","; oss << "\"" << name << "\":" << (*v ? "true" : "false"); first = false; }
    };
    auto emit_u = [&](const char *name, const std::optional<std::uint32_t> &v) {
        if (v) { if (!first) oss << ","; oss << "\"" << name << "\":" << *v; first = false; }
    };
    auto emit_s = [&](const char *name, const std::optional<std::size_t> &v) {
        if (v) { if (!first) oss << ","; oss << "\"" << name << "\":" << *v; first = false; }
    };
    auto emit_ms = [&](const char *name, const std::optional<std::chrono::milliseconds> &v) {
        if (v) { if (!first) oss << ","; oss << "\"" << name << "\":" << v->count(); first = false; }
    };
    emit_d("relay_switch_threshold", relay_switch_threshold);
    emit_d("p2p_to_relay_switch_threshold", p2p_to_relay_switch_threshold);
    emit_d("relay_to_p2p_switch_threshold", relay_to_p2p_switch_threshold);
    emit_ms("reconnecting_state_timeout_ms", reconnecting_state_timeout);
    emit_u("udp_probe_count", udp_probe_count);
    emit_d("udp_available_threshold", udp_available_threshold);
    emit_d("udp_bad_threshold", udp_bad_threshold);
    emit_ms("udp_probe_recv_timeout_ms", udp_probe_recv_timeout);
    emit_b("enable_fec_on_bad", enable_fec_on_bad);
    emit_ms("tcp_connect_timeout_ms", tcp_connect_timeout);
    emit_b("skip_udp_probe", skip_udp_probe);
    emit_d("cgn_port_dispersion_threshold", cgn_port_dispersion_threshold);
    emit_d("cgn_confidence_threshold", cgn_confidence_threshold);
    emit_s("port_predict_min_candidates", port_predict_min_candidates);
    emit_s("port_predict_max_candidates", port_predict_max_candidates);
    emit_b("ice_presume_writable_when_fully_relayed", ice_presume_writable_when_fully_relayed);
    emit_b("ice_skip_relay_to_non_relay", ice_skip_relay_to_non_relay);
    emit_b("ice_gather_continually", ice_gather_continually);
    emit_b("ice_prioritize_most_likely_pairs", ice_prioritize_most_likely_pairs);
    oss << "}";
    return oss.str();
}

NatServerConfig NatServerConfig::merge(const NatServerConfig &other) const {
    NatServerConfig r = *this;  // 复制本对象
    // other 已设置的字段覆盖 r
    if (other.relay_switch_threshold) r.relay_switch_threshold = other.relay_switch_threshold;
    if (other.p2p_to_relay_switch_threshold) r.p2p_to_relay_switch_threshold = other.p2p_to_relay_switch_threshold;
    if (other.relay_to_p2p_switch_threshold) r.relay_to_p2p_switch_threshold = other.relay_to_p2p_switch_threshold;
    if (other.reconnecting_state_timeout) r.reconnecting_state_timeout = other.reconnecting_state_timeout;
    if (other.udp_probe_count) r.udp_probe_count = other.udp_probe_count;
    if (other.udp_available_threshold) r.udp_available_threshold = other.udp_available_threshold;
    if (other.udp_bad_threshold) r.udp_bad_threshold = other.udp_bad_threshold;
    if (other.udp_probe_recv_timeout) r.udp_probe_recv_timeout = other.udp_probe_recv_timeout;
    if (other.enable_fec_on_bad) r.enable_fec_on_bad = other.enable_fec_on_bad;
    if (other.tcp_connect_timeout) r.tcp_connect_timeout = other.tcp_connect_timeout;
    if (other.skip_udp_probe) r.skip_udp_probe = other.skip_udp_probe;
    if (other.cgn_port_dispersion_threshold) r.cgn_port_dispersion_threshold = other.cgn_port_dispersion_threshold;
    if (other.cgn_confidence_threshold) r.cgn_confidence_threshold = other.cgn_confidence_threshold;
    if (other.port_predict_min_candidates) r.port_predict_min_candidates = other.port_predict_min_candidates;
    if (other.port_predict_max_candidates) r.port_predict_max_candidates = other.port_predict_max_candidates;
    if (other.ice_presume_writable_when_fully_relayed) r.ice_presume_writable_when_fully_relayed = other.ice_presume_writable_when_fully_relayed;
    if (other.ice_skip_relay_to_non_relay) r.ice_skip_relay_to_non_relay = other.ice_skip_relay_to_non_relay;
    if (other.ice_gather_continually) r.ice_gather_continually = other.ice_gather_continually;
    if (other.ice_prioritize_most_likely_pairs) r.ice_prioritize_most_likely_pairs = other.ice_prioritize_most_likely_pairs;
    return r;
}

net::UdpProbeConfig NatServerConfig::apply_to(const net::UdpProbeConfig &base) const {
    net::UdpProbeConfig r = base;
    if (udp_probe_count) r.ping_count = *udp_probe_count;
    if (udp_available_threshold) r.available_threshold = *udp_available_threshold;
    if (udp_bad_threshold) r.bad_threshold = *udp_bad_threshold;
    if (udp_probe_recv_timeout) r.recv_timeout = *udp_probe_recv_timeout;
    return r;
}

relay::FallbackConfig NatServerConfig::apply_to(const relay::FallbackConfig &base) const {
    relay::FallbackConfig r = base;
    if (enable_fec_on_bad) r.enable_fec_on_bad = *enable_fec_on_bad;
    if (tcp_connect_timeout) r.tcp_connect_timeout = *tcp_connect_timeout;
    if (skip_udp_probe) r.skip_udp_probe = *skip_udp_probe;
    return r;
}

CgnDetectorConfig NatServerConfig::apply_to(const CgnDetectorConfig &base) const {
    CgnDetectorConfig r = base;
    if (cgn_port_dispersion_threshold) r.port_dispersion_threshold = *cgn_port_dispersion_threshold;
    if (cgn_confidence_threshold) r.confidence_threshold = *cgn_confidence_threshold;
    return r;
}

PortPredictorConfig NatServerConfig::apply_to(const PortPredictorConfig &base) const {
    PortPredictorConfig r = base;
    if (port_predict_min_candidates) r.min_candidates = *port_predict_min_candidates;
    if (port_predict_max_candidates) r.max_candidates = *port_predict_max_candidates;
    return r;
}

IceSessionConfig NatServerConfig::apply_to(const IceSessionConfig &base) const {
    IceSessionConfig r = base;
    if (ice_presume_writable_when_fully_relayed) r.presume_writable_when_fully_relayed = *ice_presume_writable_when_fully_relayed;
    if (ice_skip_relay_to_non_relay) r.skip_relay_to_non_relay_connections = *ice_skip_relay_to_non_relay;
    if (ice_gather_continually) r.gather_continually = *ice_gather_continually;
    if (ice_prioritize_most_likely_pairs) r.prioritize_most_likely_candidate_pairs = *ice_prioritize_most_likely_pairs;
    return r;
}

std::size_t NatServerConfig::set_field_count() const {
    std::size_t n = 0;
    if (relay_switch_threshold) ++n;
    if (p2p_to_relay_switch_threshold) ++n;
    if (relay_to_p2p_switch_threshold) ++n;
    if (reconnecting_state_timeout) ++n;
    if (udp_probe_count) ++n;
    if (udp_available_threshold) ++n;
    if (udp_bad_threshold) ++n;
    if (udp_probe_recv_timeout) ++n;
    if (enable_fec_on_bad) ++n;
    if (tcp_connect_timeout) ++n;
    if (skip_udp_probe) ++n;
    if (cgn_port_dispersion_threshold) ++n;
    if (cgn_confidence_threshold) ++n;
    if (port_predict_min_candidates) ++n;
    if (port_predict_max_candidates) ++n;
    if (ice_presume_writable_when_fully_relayed) ++n;
    if (ice_skip_relay_to_non_relay) ++n;
    if (ice_gather_continually) ++n;
    if (ice_prioritize_most_likely_pairs) ++n;
    return n;
}

// ============================================================================
// ServerConfigManager 实现
// ============================================================================

ServerConfigManager &ServerConfigManager::instance() {
    static ServerConfigManager inst;
    return inst;
}

bool ServerConfigManager::update(const std::string &json) {
    NatServerConfig parsed = NatServerConfig::from_json(json);
    // 简单校验：解析后至少有一个字段（空 JSON {} 也算成功，清空配置）
    // from_json 失败时返回空配置（全 nullopt），无法区分"空 JSON"和"解析失败"
    // 这里统一视为成功（空 JSON 合法，清空配置）
    NatServerConfig new_cfg;
    ConfigChangedCallback cb_copy;
    {
        std::unique_lock<std::shared_mutex> lk(mu_);
        new_cfg = config_.merge(parsed);  // 合并：parsed 已设置字段覆盖现有
        config_ = new_cfg;
        cb_copy = callback_;
    }
    LINOH_INFO("ServerConfig: updated, set_fields=", new_cfg.set_field_count());
    if (cb_copy) cb_copy(new_cfg);
    return true;
}

NatServerConfig ServerConfigManager::config() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return config_;
}

void ServerConfigManager::set_changed_callback(ConfigChangedCallback cb) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    callback_ = std::move(cb);
}

void ServerConfigManager::reset() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    config_ = NatServerConfig{};
}

} // namespace linoh::nat
