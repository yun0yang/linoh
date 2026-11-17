// channel.cpp — 多模态通道实现（P5-A-1）
//
// 当前阶段（P5-A-1）仅实现序列化/反序列化与配置工具函数；
// FEC、加密分级、多路径 strip 等具体逻辑在 P5-B 阶段落地。

#include "linoh/multimodal/channel.hpp"

#include <sstream>
#include <string>

namespace linoh::multimodal {

namespace {

/// 简易 JSON 风格键值对解析（仅支持单层扁平结构，避免引入完整 JSON 库）
/// 格式示例：{"type":"llm_hidden","mtu":1280,"fec":"reed_solomon","crypto":"strong"}
struct KvParser {
    std::string s;
    std::size_t pos{0};

    bool skip_ws() {
        while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n')) pos++;
        return pos < s.size();
    }

    bool expect(char c) {
        if (!skip_ws() || s[pos] != c) return false;
        pos++;
        return true;
    }

    bool parse_string(std::string &out) {
        if (!expect('"')) return false;
        std::size_t start = pos;
        while (pos < s.size() && s[pos] != '"') pos++;
        if (pos >= s.size()) return false;
        out = s.substr(start, pos - start);
        pos++;  // 跳过结束引号
        return true;
    }

    bool parse_uint(std::uint64_t &out) {
        if (!skip_ws() || !std::isdigit(static_cast<unsigned char>(s[pos]))) return false;
        std::uint64_t v = 0;
        while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) {
            v = v * 10 + static_cast<std::uint64_t>(s[pos] - '0');
            pos++;
        }
        out = v;
        return true;
    }

    // B10 fix(2026-07-20): 跳过任意 JSON 值（字符串/数字/布尔/null/对象/数组）。
    // 原 unknown-key 分支用 parse_string 跳过，遇到数字/布尔值会失败导致后续键全丢。
    bool skip_value() {
        if (!skip_ws() || pos >= s.size()) return false;
        char ch = s[pos];
        if (ch == '"') {
            // 字符串
            std::string dummy;
            return parse_string(dummy);
        } else if (ch == 't') {
            // true
            if (s.compare(pos, 4, "true") == 0) { pos += 4; return true; }
            return false;
        } else if (ch == 'f') {
            // false
            if (s.compare(pos, 5, "false") == 0) { pos += 5; return true; }
            return false;
        } else if (ch == 'n') {
            // null
            if (s.compare(pos, 4, "null") == 0) { pos += 4; return true; }
            return false;
        } else if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch))) {
            // 数字（含负数）
            if (ch == '-') pos++;
            while (pos < s.size() &&
                   (std::isdigit(static_cast<unsigned char>(s[pos])) || s[pos] == '.' ||
                    s[pos] == 'e' || s[pos] == 'E' || s[pos] == '+' || s[pos] == '-')) {
                pos++;
            }
            return true;
        } else if (ch == '{') {
            // 对象：匹配花括号深度
            int depth = 0;
            while (pos < s.size()) {
                if (s[pos] == '{') depth++;
                else if (s[pos] == '}') { depth--; if (depth == 0) { pos++; return true; } }
                else if (s[pos] == '"') {
                    std::string dummy;
                    size_t saved = pos;
                    if (!parse_string(dummy)) { pos = saved; pos++; }
                    continue;
                }
                pos++;
            }
            return false;
        } else if (ch == '[') {
            // 数组：匹配方括号深度
            int depth = 0;
            while (pos < s.size()) {
                if (s[pos] == '[') depth++;
                else if (s[pos] == ']') { depth--; if (depth == 0) { pos++; return true; } }
                else if (s[pos] == '"') {
                    std::string dummy;
                    size_t saved = pos;
                    if (!parse_string(dummy)) { pos = saved; pos++; }
                    continue;
                }
                pos++;
            }
            return false;
        }
        return false;
    }
};

}  // namespace

/// ChannelConfig 序列化为 JSON 风格字符串
std::string channel_config_to_json(const ChannelConfig &c) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"" << channel_type_name(c.type) << "\"";
    oss << ",\"mtu\":" << c.preferred_mtu;
    oss << ",\"max_streams\":" << c.max_stream_concurrency;
    oss << ",\"fec_enabled\":" << (c.fec_enabled ? "true" : "false");
    oss << ",\"fec_type\":\"" << fec_type_name(c.fec_type) << "\"";
    oss << ",\"fec_k\":" << c.fec_data_blocks;
    oss << ",\"fec_m\":" << c.fec_recovery_blocks;
    oss << ",\"multipath_strip\":" << (c.multipath_strip ? "true" : "false");
    oss << ",\"crypto\":\"" << crypto_level_name(c.crypto_level) << "\"";
    oss << "}";
    return oss.str();
}

/// 从 JSON 字符串反序列化 ChannelConfig
/// 解析失败时返回 for_channel(type) 默认配置
ChannelConfig channel_config_from_json(std::string_view json, ChannelType default_type) {
    ChannelConfig c = ChannelConfig::for_channel(default_type);

    KvParser p{std::string(json)};
    if (!p.expect('{')) return c;

    while (true) {
        std::string key;
        if (!p.parse_string(key)) break;
        if (!p.expect(':')) break;

        if (key == "type") {
            std::string v;
            if (p.parse_string(v)) {
                if (v == "control")              c.type = ChannelType::CONTROL;
                else if (v == "llm_hidden")      c.type = ChannelType::LLM_HIDDEN;
                else if (v == "img_feature")     c.type = ChannelType::IMG_FEATURE;
                else if (v == "video_feature")   c.type = ChannelType::VIDEO_FEATURE;
                else if (v == "audio_feature")   c.type = ChannelType::AUDIO_FEATURE;
                else if (v == "fusion")          c.type = ChannelType::FUSION;
            }
        } else if (key == "mtu") {
            std::uint64_t v = 0;
            if (p.parse_uint(v)) c.preferred_mtu = static_cast<std::uint16_t>(v);
        } else if (key == "max_streams") {
            std::uint64_t v = 0;
            if (p.parse_uint(v)) c.max_stream_concurrency = static_cast<std::size_t>(v);
        } else if (key == "fec_enabled") {
            if (p.skip_ws() && p.s[p.pos] == 't') {
                c.fec_enabled = true;
                p.pos += 4;  // skip "true"
            } else if (p.skip_ws() && p.s[p.pos] == 'f') {
                c.fec_enabled = false;
                p.pos += 5;  // skip "false"
            }
        } else if (key == "fec_type") {
            std::string v;
            if (p.parse_string(v)) {
                if (v == "none")              c.fec_type = FecType::None;
                else if (v == "xor")          c.fec_type = FecType::Xor;
                else if (v == "reed_solomon") c.fec_type = FecType::ReedSolomon;
            }
        } else if (key == "fec_k") {
            std::uint64_t v = 0;
            if (p.parse_uint(v)) c.fec_data_blocks = static_cast<std::size_t>(v);
        } else if (key == "fec_m") {
            std::uint64_t v = 0;
            if (p.parse_uint(v)) c.fec_recovery_blocks = static_cast<std::size_t>(v);
        } else if (key == "multipath_strip") {
            if (p.skip_ws() && p.s[p.pos] == 't') {
                c.multipath_strip = true;
                p.pos += 4;
            } else if (p.skip_ws() && p.s[p.pos] == 'f') {
                c.multipath_strip = false;
                p.pos += 5;
            }
        } else if (key == "crypto") {
            std::string v;
            if (p.parse_string(v)) {
                if (v == "none")           c.crypto_level = CryptoLevel::None;
                else if (v == "light")     c.crypto_level = CryptoLevel::Light;
                else if (v == "standard")  c.crypto_level = CryptoLevel::Standard;
                else if (v == "strong")    c.crypto_level = CryptoLevel::Strong;
                else if (v == "maximum")   c.crypto_level = CryptoLevel::Maximum;
            }
        } else {
            // B10 fix(2026-07-20): 未知键用 skip_value() 跳过任意类型值，
            // 替代原 parse_string(dummy)。原实现遇到数字/布尔值会失败导致后续键全丢。
            if (!p.skip_value()) break;
        }

        if (!p.expect(',')) break;
    }

    return c;
}

}  // namespace linoh::multimodal
