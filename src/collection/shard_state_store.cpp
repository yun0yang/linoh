// =============================================================================
// shard_state_store.cpp — v3.7.4 可靠性强化：断点续传状态存储实现
//
// 复用 v3.7.0 的 sha256（util/crypto.hpp）+ atomic_write_file（util/atomic_write.hpp）
// 手写极简 JSON 序列化器（与 model_manifest 风格一致）
// =============================================================================

#include "linoh/collection/shard_state_store.hpp"

#include "linoh/collection/model_manifest.hpp"  // ShardEntry
#include "linoh/util/atomic_write.hpp"
#include "linoh/util/crypto.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace linoh::collection {

namespace {

// =========================================================================
// 内部辅助：字符串转义/反转义（JSON 字符串）
// =========================================================================

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            case '\r': out += "\\r"; break;
            default:
                out += c;
        }
    }
    return out;
}

std::string json_unescape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char next = s[i + 1];
            switch (next) {
                case '"':  out += '"';  ++i; break;
                case '\\': out += '\\'; ++i; break;
                case 'n':  out += '\n'; ++i; break;
                case 't':  out += '\t'; ++i; break;
                case 'r':  out += '\r'; ++i; break;
                case '/':  out += '/';  ++i; break;
                default:
                    out += s[i];
            }
        } else {
            out += s[i];
        }
    }
    return out;
}

// =========================================================================
// 内部辅助：当前时间戳（毫秒）
// =========================================================================

std::uint64_t now_ms() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch());
    return static_cast<std::uint64_t>(ms.count());
}

// =========================================================================
// 内部辅助：sha256 → 64 字符 hex
// =========================================================================

std::string sha256_to_hex(
        const std::array<uint8_t, crypto::SHA256::kDigestSize> &hash) {
    static const char *kHexDigits = "0123456789abcdef";
    std::string out(64, '0');
    for (std::size_t i = 0; i < hash.size(); ++i) {
        out[i * 2] = kHexDigits[(hash[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHexDigits[hash[i] & 0x0F];
    }
    return out;
}

// =========================================================================
// 内部辅助：极简 JSON 解析器（与 model_manifest.cpp 风格一致）
// =========================================================================

class JsonParser {
public:
    explicit JsonParser(std::string_view text) : text_(text), pos_(0) {}

    void skip_ws() {
        while (pos_ < text_.size()) {
            char c = text_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    char peek() {
        return pos_ < text_.size() ? text_[pos_] : '\0';
    }

    bool expect(char c) {
        skip_ws();
        if (pos_ < text_.size() && text_[pos_] == c) {
            ++pos_;
            return true;
        }
        return false;
    }

    void advance(std::size_t n = 1) {
        pos_ += n;
        if (pos_ > text_.size()) pos_ = text_.size();
    }

    bool parse_string(std::string &out) {
        out.clear();
        ++pos_;  // 消费开头的 "
        std::string raw;
        while (pos_ < text_.size()) {
            char c = text_[pos_];
            if (c == '\\' && pos_ + 1 < text_.size()) {
                raw += c;
                raw += text_[pos_ + 1];
                pos_ += 2;
                continue;
            }
            if (c == '"') {
                ++pos_;
                out = json_unescape(raw);
                return true;
            }
            raw += c;
            ++pos_;
        }
        return false;
    }

    bool parse_uint64(std::uint64_t &out) {
        skip_ws();
        std::uint64_t v = 0;
        bool any = false;
        while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
            v = v * 10 + static_cast<std::uint64_t>(text_[pos_] - '0');
            ++pos_;
            any = true;
        }
        if (!any) return false;
        out = v;
        return true;
    }

    std::string_view peek_substr(std::size_t n) const {
        if (pos_ + n > text_.size()) return {};
        return text_.substr(pos_, n);
    }

    bool match_literal(std::string_view literal) {
        if (peek_substr(literal.size()) != literal) return false;
        pos_ += literal.size();
        return true;
    }

    std::size_t pos() const { return pos_; }
    std::size_t size() const { return text_.size(); }

private:
    std::string_view text_;
    std::size_t pos_;
};

} // anonymous namespace

// =============================================================================
// ShardStateStore 构造/析构
// =============================================================================

ShardStateStore::ShardStateStore(std::string store_path)
    : store_path_(std::move(store_path)) {}

ShardStateStore::~ShardStateStore() = default;

// =============================================================================
// JSON 序列化（含 store 自身 sha256 校验）
// =============================================================================

namespace {

/// 序列化 states 为 JSON（不含 store_hash 字段，用于 hash 计算）
std::string states_to_json_canonical(const std::vector<ShardState> &states) {
    std::ostringstream oss;
    oss << "{\"states\":[";
    for (std::size_t i = 0; i < states.size(); ++i) {
        const ShardState &s = states[i];
        oss << "{"
            << "\"layer_index\":" << s.layer_index << ","
            << "\"filename\":\"" << json_escape(s.filename) << "\","
            << "\"total_size\":" << s.total_size << ","
            << "\"downloaded_bytes\":" << s.downloaded_bytes << ","
            << "\"sha256\":\"" << json_escape(s.sha256_hex) << "\","
            << "\"verified\":" << (s.verified ? "true" : "false") << ","
            << "\"timestamp_ms\":" << s.timestamp_ms << ","
            << "\"retry_count\":" << s.retry_count
            << "}";
        if (i + 1 < states.size()) oss << ",";
    }
    oss << "]}";
    return oss.str();
}

/// 计算 canonical JSON 的 sha256 hex
std::string compute_store_hash(const std::vector<ShardState> &states) {
    std::string canonical = states_to_json_canonical(states);
    std::span<const uint8_t> data(
        reinterpret_cast<const uint8_t *>(canonical.data()),
        canonical.size());
    auto hash = crypto::SHA256::hash(data);
    return sha256_to_hex(hash);
}

/// 序列化为完整 JSON（含 store_hash + schema_version + atomic_committed）
std::string states_to_json_full(const std::vector<ShardState> &states,
                                  std::string_view store_hash,
                                  bool atomic_committed) {
    std::ostringstream oss;
    oss << "{"
        << "\"schema_version\":1,"
        << "\"atomic_committed\":" << (atomic_committed ? "true" : "false") << ","
        << "\"store_hash\":\"" << json_escape(store_hash) << "\","
        << "\"states\":[";
    for (std::size_t i = 0; i < states.size(); ++i) {
        const ShardState &s = states[i];
        oss << "{"
            << "\"layer_index\":" << s.layer_index << ","
            << "\"filename\":\"" << json_escape(s.filename) << "\","
            << "\"total_size\":" << s.total_size << ","
            << "\"downloaded_bytes\":" << s.downloaded_bytes << ","
            << "\"sha256\":\"" << json_escape(s.sha256_hex) << "\","
            << "\"verified\":" << (s.verified ? "true" : "false") << ","
            << "\"timestamp_ms\":" << s.timestamp_ms << ","
            << "\"retry_count\":" << s.retry_count
            << "}";
        if (i + 1 < states.size()) oss << ",";
    }
    oss << "]}";
    return oss.str();
}

} // anonymous namespace

// =============================================================================
// 文件读写
// =============================================================================

bool ShardStateStore::load_from_file() {
    std::ifstream ifs(store_path_, std::ios::binary);
    if (!ifs.is_open()) return false;  // 文件不存在

    std::ostringstream oss;
    oss << ifs.rdbuf();
    std::string content = oss.str();

    // 解析 JSON
    JsonParser p(content);
    p.skip_ws();
    if (!p.expect('{')) return false;

    states_.clear();
    std::string loaded_store_hash;
    bool atomic_committed = true;  // 默认值（兼容旧版）

    while (true) {
        p.skip_ws();
        if (p.peek() == '}') { p.advance(); break; }
        if (p.peek() != '"') return false;
        std::string key;
        if (!p.parse_string(key)) return false;
        if (!p.expect(':')) return false;

        p.skip_ws();
        char c = p.peek();

        if (key == "states" && c == '[') {
            p.advance();  // 消费 [
            while (true) {
                p.skip_ws();
                if (p.peek() == ']') { p.advance(); break; }
                if (!p.expect('{')) return false;

                ShardState state;
                while (true) {
                    p.skip_ws();
                    if (p.peek() == '}') { p.advance(); break; }

                    std::string skey;
                    if (p.peek() != '"') return false;
                    if (!p.parse_string(skey)) return false;
                    if (!p.expect(':')) return false;

                    p.skip_ws();
                    char sc = p.peek();
                    if (sc == '"') {
                        std::string sval;
                        if (!p.parse_string(sval)) return false;
                        if (skey == "filename") {
                            state.filename = sval;
                        } else if (skey == "sha256") {
                            state.sha256_hex = sval;
                        }
                    } else if (sc >= '0' && sc <= '9') {
                        std::uint64_t sv;
                        if (!p.parse_uint64(sv)) return false;
                        if (skey == "layer_index") {
                            state.layer_index = static_cast<std::uint32_t>(sv);
                        } else if (skey == "total_size") {
                            state.total_size = sv;
                        } else if (skey == "downloaded_bytes") {
                            state.downloaded_bytes = sv;
                        } else if (skey == "timestamp_ms") {
                            state.timestamp_ms = sv;
                        } else if (skey == "retry_count") {
                            state.retry_count = static_cast<int>(sv);
                        }
                    } else if (sc == 't' || sc == 'f') {
                        if (sc == 't') {
                            if (!p.match_literal("true")) return false;
                            if (skey == "verified") state.verified = true;
                        } else {
                            if (!p.match_literal("false")) return false;
                            if (skey == "verified") state.verified = false;
                        }
                    } else {
                        return false;
                    }

                    p.skip_ws();
                    if (p.peek() == ',') { p.advance(); continue; }
                    if (p.peek() == '}') { p.advance(); break; }
                }
                states_.push_back(std::move(state));

                p.skip_ws();
                if (p.peek() == ',') { p.advance(); continue; }
                if (p.peek() == ']') { p.advance(); break; }
            }
        } else if (key == "store_hash" && c == '"') {
            if (!p.parse_string(loaded_store_hash)) return false;
        } else if (key == "atomic_committed" && (c == 't' || c == 'f')) {
            if (c == 't') {
                if (!p.match_literal("true")) return false;
                atomic_committed = true;
            } else {
                if (!p.match_literal("false")) return false;
                atomic_committed = false;
            }
        } else if (key == "schema_version" && c >= '0' && c <= '9') {
            std::uint64_t v;
            if (!p.parse_uint64(v)) return false;
            // schema_version 仅记录，暂不使用（v1 当前唯一版本）
        } else if (c == '"') {
            std::string val;
            if (!p.parse_string(val)) return false;
        } else if (c >= '0' && c <= '9') {
            std::uint64_t v;
            if (!p.parse_uint64(v)) return false;
        } else if (c == '[') {
            // 未知数组，简化处理：跳过到匹配 ]
            int depth = 1;
            p.advance();
            while (depth > 0 && p.pos() < p.size()) {
                char ch = p.peek();
                if (ch == '[') ++depth;
                else if (ch == ']') --depth;
                p.advance();
            }
        } else {
            return false;
        }

        p.skip_ws();
        if (p.peek() == ',') { p.advance(); continue; }
        if (p.peek() == '}') { p.advance(); break; }
    }

    // 校验 atomic_committed（v3.7.2 机制）
    if (!atomic_committed) {
        // 写入未完成，视为损坏
        states_.clear();
        return false;
    }

    // 校验 store_hash（若存在）
    if (!loaded_store_hash.empty()) {
        std::string expected = compute_store_hash(states_);
        if (loaded_store_hash != expected) {
            // hash 不匹配，状态文件损坏
            states_.clear();
            return false;
        }
    }

    // 按 layer_index 升序排序
    std::sort(states_.begin(), states_.end(),
              [](const ShardState &a, const ShardState &b) {
                  return a.layer_index < b.layer_index;
              });

    return true;
}

bool ShardStateStore::save_atomic() {
    namespace fs = std::filesystem;
    fs::path target(store_path_);
    fs::path parent = target.parent_path();
    if (parent.empty()) parent = fs::current_path();
    std::error_code ec;
    fs::create_directories(parent, ec);

    // 计算当前 states 的 hash
    std::string store_hash = compute_store_hash(states_);

    // 使用 atomic_write_file 直接写入完整 JSON（atomic_committed=true）
    // 注：简化流程，直接写 atomic_committed=true 版本
    // 若需更严格的 v3.7.2 双阶段写入，可参考 write_manifest_atomic 实现
    std::string json = states_to_json_full(states_, store_hash, true);
    std::span<const uint8_t> data(
        reinterpret_cast<const uint8_t *>(json.data()),
        json.size());
    return util::atomic_write_file(store_path_, data);
}

bool ShardStateStore::file_exists() const {
    namespace fs = std::filesystem;
    std::error_code ec;
    return fs::exists(fs::path(store_path_), ec);
}

bool ShardStateStore::remove_file() {
    namespace fs = std::filesystem;
    std::error_code ec;
    return fs::remove(fs::path(store_path_), ec);
}

// =============================================================================
// CRUD 操作
// =============================================================================

ShardState *ShardStateStore::find(std::uint32_t layer_index) {
    for (auto &s : states_) {
        if (s.layer_index == layer_index) return &s;
    }
    return nullptr;
}

const ShardState *ShardStateStore::find(std::uint32_t layer_index) const {
    for (const auto &s : states_) {
        if (s.layer_index == layer_index) return &s;
    }
    return nullptr;
}

bool ShardStateStore::upsert(const ShardState &state) {
    ShardState *existing = find(state.layer_index);
    if (existing) {
        *existing = state;
        return true;
    }
    states_.push_back(state);
    // 保持 layer_index 升序
    std::sort(states_.begin(), states_.end(),
              [](const ShardState &a, const ShardState &b) {
                  return a.layer_index < b.layer_index;
              });
    return true;
}

bool ShardStateStore::remove(std::uint32_t layer_index) {
    for (auto it = states_.begin(); it != states_.end(); ++it) {
        if (it->layer_index == layer_index) {
            states_.erase(it);
            return true;
        }
    }
    return false;
}

void ShardStateStore::clear() noexcept {
    states_.clear();
}

// =============================================================================
// 查询辅助
// =============================================================================

std::size_t ShardStateStore::completed_count() const {
    std::size_t n = 0;
    for (const auto &s : states_) {
        if (s.is_complete() && s.verified) ++n;
    }
    return n;
}

std::size_t ShardStateStore::resume_count() const {
    std::size_t n = 0;
    for (const auto &s : states_) {
        if (s.needs_resume()) ++n;
    }
    return n;
}

std::size_t ShardStateStore::pending_count(
    const std::vector<ShardEntry> &manifest_shards) const {
    std::size_t n = 0;
    for (const auto &shard : manifest_shards) {
        const ShardState *s = find(shard.layer_index);
        if (!s || s->downloaded_bytes == 0) ++n;
    }
    return n;
}

std::uint64_t ShardStateStore::total_downloaded_bytes() const {
    std::uint64_t total = 0;
    for (const auto &s : states_) {
        total += s.downloaded_bytes;
    }
    return total;
}

// =============================================================================
// 便捷辅助函数
// =============================================================================

std::size_t sync_from_manifest(
    ShardStateStore &store,
    const std::vector<ShardEntry> &manifest_shards) {
    std::size_t added = 0;
    for (const auto &shard : manifest_shards) {
        ShardState *existing = store.find(shard.layer_index);
        if (existing) {
            // 更新 manifest 信息（保留下载进度）
            existing->filename = shard.filename;
            existing->total_size = shard.size;
            existing->sha256_hex = shard.sha256_hex;
        } else {
            ShardState state;
            state.layer_index = shard.layer_index;
            state.filename = shard.filename;
            state.total_size = shard.size;
            state.sha256_hex = shard.sha256_hex;
            state.downloaded_bytes = 0;
            state.verified = false;
            state.timestamp_ms = now_ms();
            state.retry_count = 0;
            store.upsert(state);
            ++added;
        }
    }
    return added;
}

bool mark_shard_completed(ShardStateStore &store,
                            std::uint32_t layer_index) {
    ShardState *s = store.find(layer_index);
    if (!s) return false;
    s->downloaded_bytes = s->total_size;
    s->verified = true;
    s->timestamp_ms = now_ms();
    return true;
}

bool mark_shard_progress(ShardStateStore &store,
                           std::uint32_t layer_index,
                           std::uint64_t downloaded_bytes) {
    ShardState *s = store.find(layer_index);
    if (!s) return false;
    s->downloaded_bytes = downloaded_bytes;
    s->timestamp_ms = now_ms();
    if (s->is_complete()) {
        s->verified = false;  // 完整下载但未校验，verified=false
    }
    return true;
}

} // namespace linoh::collection
