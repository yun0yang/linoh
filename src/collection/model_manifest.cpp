// =============================================================================
// model_manifest.cpp — v3.7.1 可靠性强化：内容寻址 manifest 实现
//
// 复用 v3.7.0 的 SHA256（util/crypto.hpp）和 atomic_write_file（util/atomic_write.hpp）
// 手写极简 JSON 序列化器（字段固定、无外部依赖）
// =============================================================================

#include "linoh/collection/model_manifest.hpp"

#include "linoh/util/atomic_write.hpp"
#include "linoh/util/crypto.hpp"

#include <algorithm>
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

/// JSON 字符串转义（"  \  换行  制表符  回车）
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
                // 非 ASCII 字节（>= 0x80）原样输出（UTF-8 透传）
                out += c;
        }
    }
    return out;
}

/// JSON 字符串反转义
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
                    // 未知转义，保留反斜杠 + 字符
                    out += s[i];
            }
        } else {
            out += s[i];
        }
    }
    return out;
}

// =========================================================================
// 内部辅助：文件 sha256 计算（流式，复用 linoh::crypto::SHA256）
// =========================================================================

/// 计算文件的 sha256（32 字节）
/// @return true 成功；false 文件打开失败
bool compute_file_sha256(std::string_view file_path,
                          std::array<uint8_t, crypto::SHA256::kDigestSize> &out_hash,
                          std::uint64_t &out_size) {
    out_size = 0;
    std::ifstream ifs((std::string(file_path)), std::ios::binary);
    if (!ifs.is_open()) return false;

    crypto::SHA256 ctx;
    constexpr std::size_t kBufSize = 64 * 1024;  // 64KiB 读缓冲
    std::vector<uint8_t> buffer(kBufSize);

    while (true) {
        ifs.read(reinterpret_cast<char *>(buffer.data()),
                 static_cast<std::streamsize>(buffer.size()));
        std::streamsize n = ifs.gcount();
        if (n <= 0) break;
        std::span<const uint8_t> chunk(buffer.data(),
                                        static_cast<std::size_t>(n));
        ctx.update(chunk);
        out_size += static_cast<std::uint64_t>(n);
    }

    out_hash = ctx.finalize();
    return true;
}

/// sha256 字节数组 → 64 字符小写十六进制字符串
std::string sha256_to_hex(
        const std::array<uint8_t, crypto::SHA256::kDigestSize> &hash) {
    static const char *kHexDigits = "0123456789abcdef";
    std::string out(64, '0');
    for (std::size_t i = 0; i < hash.size(); ++i) {
        out[i * 2]     = kHexDigits[(hash[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHexDigits[hash[i] & 0x0F];
    }
    return out;
}

// =========================================================================
// 内部辅助：极简 JSON 解析器（递归下降，仅支持 manifest 所需结构）
// =========================================================================

class JsonParser {
public:
    explicit JsonParser(std::string_view text) : text_(text), pos_(0) {}

    /// 跳过空白字符
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

    /// 当前字符
    char peek() {
        return pos_ < text_.size() ? text_[pos_] : '\0';
    }

    /// 消费指定字符，失败返回 false
    bool expect(char c) {
        skip_ws();
        if (pos_ < text_.size() && text_[pos_] == c) {
            ++pos_;
            return true;
        }
        return false;
    }

    /// 前进 n 个字符（pos_ 是 private，外部通过此方法修改）
    void advance(std::size_t n = 1) {
        pos_ += n;
        if (pos_ > text_.size()) pos_ = text_.size();
    }

    /// 解析字符串（已消费前导 "）
    bool parse_string(std::string &out) {
        out.clear();
        // 假设调用前已确认 peek() == '"'
        ++pos_;  // 消费开头的 "
        std::string raw;
        while (pos_ < text_.size()) {
            char c = text_[pos_];
            if (c == '\\' && pos_ + 1 < text_.size()) {
                // 转义字符：把 \ 和下一个字符一起加入 raw
                // 防止 \" 被误认为字符串结束
                raw += c;
                raw += text_[pos_ + 1];
                pos_ += 2;
                continue;
            }
            if (c == '"') {
                ++pos_;  // 消费结尾的 "
                out = json_unescape(raw);
                return true;
            }
            raw += c;
            ++pos_;
        }
        return false;  // 未找到结尾的 "
    }

    /// 解析无符号整数
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

    std::size_t pos() const { return pos_; }
    std::size_t size() const { return text_.size(); }

    /// 返回当前位置开始的 n 个字符的子串（不前进 pos_）
    /// @note 若剩余字符不足 n，返回空串
    std::string_view peek_substr(std::size_t n) const {
        if (pos_ + n > text_.size()) return {};
        return text_.substr(pos_, n);
    }

    /// 尝试匹配并消费字面量关键字（如 "true"、"false"、"null"）
    /// @return true 若匹配成功并消费；false 不匹配（不消费 pos_）
    bool match_literal(std::string_view literal) {
        if (peek_substr(literal.size()) != literal) return false;
        pos_ += literal.size();
        return true;
    }

private:
    std::string_view text_;
    std::size_t pos_;
};

} // anonymous namespace

// =============================================================================
// ModelManifest JSON 序列化
// =============================================================================

std::string ModelManifest::to_json(bool pretty) const {
    std::ostringstream oss;
    const char *indent = pretty ? "  " : "";
    const char *nl = pretty ? "\n" : "";
    const char *sep = pretty ? ", " : ",";
    const char *kvs = pretty ? ": " : ":";

    oss << "{" << nl;
    oss << indent << "\"schema_version\":" << schema_version << sep << nl;
    oss << indent << "\"atomic_committed\":" << (atomic_committed ? "true" : "false") << sep << nl;
    oss << indent << "\"model_name\":\"" << json_escape(model_name) << "\"" << sep << nl;
    oss << indent << "\"model_version\":\"" << json_escape(model_version) << "\"" << sep << nl;
    oss << indent << "\"total_layers\":" << total_layers << sep << nl;
    oss << indent << "\"manifest_hash\":\"" << json_escape(manifest_hash) << "\"" << sep << nl;
    oss << indent << "\"shards\":[" << nl;

    for (std::size_t i = 0; i < shards.size(); ++i) {
        const ShardEntry &s = shards[i];
        if (pretty) oss << indent << "  ";
        oss << "{"
            << "\"layer_index\":" << s.layer_index << sep
            << "\"filename\":\"" << json_escape(s.filename) << "\"" << sep
            << "\"sha256\":\"" << json_escape(s.sha256_hex) << "\"" << sep
            << "\"size\":" << s.size << sep
            << "\"version\":" << s.version
            << "}";
        if (i + 1 < shards.size()) oss << sep;
        oss << nl;
    }

    oss << indent << "]" << nl;
    oss << "}";
    return oss.str();
}

bool ModelManifest::from_json(std::string_view json, ModelManifest &out) {
    JsonParser p(json);
    p.skip_ws();
    if (!p.expect('{')) return false;

    out = ModelManifest{};  // 重置为默认

    while (true) {
        p.skip_ws();
        if (p.peek() == '}') { p.advance(); break; }

        // 解析 key
        if (p.peek() != '"') return false;
        std::string key;
        if (!p.parse_string(key)) return false;

        if (!p.expect(':')) return false;

        // 解析 value
        p.skip_ws();
        char c = p.peek();
        if (c == '"') {
            // 字符串值
            // 已知数值/bool 字段不接受字符串值（类型检查）
            if (key == "total_layers" || key == "schema_version" ||
                key == "atomic_committed") return false;
            std::string val;
            if (!p.parse_string(val)) return false;
            if (key == "model_name") {
                out.model_name = val;
            } else if (key == "model_version") {
                out.model_version = val;
            } else if (key == "manifest_hash") {
                out.manifest_hash = val;
            } else {
                // 未知字符串字段，忽略
            }
        } else if (c >= '0' && c <= '9') {
            // 数值
            // 已知字符串/bool 字段不接受数值（类型检查）
            if (key == "model_name" || key == "model_version" ||
                key == "manifest_hash" || key == "atomic_committed") return false;
            std::uint64_t v;
            if (!p.parse_uint64(v)) return false;
            if (key == "total_layers") {
                out.total_layers = static_cast<std::uint32_t>(v);
            } else if (key == "schema_version") {
                out.schema_version = static_cast<std::uint32_t>(v);
            } else {
                // 未知数值字段，忽略
            }
        } else if (c == 't' || c == 'f') {
            // bool 值（true/false）
            // 已知非 bool 字段不接受 bool 值（类型检查）
            if (key == "model_name" || key == "model_version" ||
                key == "manifest_hash" || key == "total_layers" ||
                key == "schema_version") return false;
            // 解析 true / false
            if (c == 't') {
                if (!p.match_literal("true")) return false;
                if (key == "atomic_committed") out.atomic_committed = true;
            } else {  // c == 'f'
                if (!p.match_literal("false")) return false;
                if (key == "atomic_committed") out.atomic_committed = false;
            }
        } else if (c == '[') {
            // shards 数组
            p.advance();  // 消费 [
            if (key == "shards") {
                while (true) {
                    p.skip_ws();
                    if (p.peek() == ']') { p.advance(); break; }

                    // 解析 shard 对象
                    if (!p.expect('{')) return false;
                    ShardEntry shard;
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
                                shard.filename = sval;
                            } else if (skey == "sha256") {
                                shard.sha256_hex = sval;
                            }
                        } else if (sc >= '0' && sc <= '9') {
                            std::uint64_t sv;
                            if (!p.parse_uint64(sv)) return false;
                            if (skey == "layer_index") {
                                shard.layer_index = static_cast<std::uint32_t>(sv);
                            } else if (skey == "size") {
                                shard.size = sv;
                            } else if (skey == "version") {
                                shard.version = static_cast<std::uint32_t>(sv);
                            }
                        } else {
                            return false;
                        }

                        p.skip_ws();
                        if (p.peek() == ',') { p.advance(); continue; }
                        if (p.peek() == '}') { p.advance(); break; }
                    }
                    out.shards.push_back(std::move(shard));

                    p.skip_ws();
                    if (p.peek() == ',') { p.advance(); continue; }
                    if (p.peek() == ']') { p.advance(); break; }
                }
            } else {
                // 未知数组，跳过（简化处理：不支持嵌套未知数组）
                return false;
            }
        } else {
            return false;
        }

        p.skip_ws();
        if (p.peek() == ',') { p.advance(); continue; }
        if (p.peek() == '}') { p.advance(); break; }
    }

    return true;
}

// =============================================================================
// manifest_hash 计算（sha256 of canonical form without manifest_hash field）
// =============================================================================

void ModelManifest::compute_hash() {
    // 构造不含 manifest_hash 字段的 canonical JSON（v3.7.2: 含 schema_version + atomic_committed）
    std::ostringstream oss;
    oss << "{"
        << "\"schema_version\":" << schema_version << ","
        << "\"atomic_committed\":" << (atomic_committed ? "true" : "false") << ","
        << "\"model_name\":\"" << json_escape(model_name) << "\","
        << "\"model_version\":\"" << json_escape(model_version) << "\","
        << "\"total_layers\":" << total_layers << ","
        << "\"shards\":[";

    for (std::size_t i = 0; i < shards.size(); ++i) {
        const ShardEntry &s = shards[i];
        oss << "{"
            << "\"layer_index\":" << s.layer_index << ","
            << "\"filename\":\"" << json_escape(s.filename) << "\","
            << "\"sha256\":\"" << json_escape(s.sha256_hex) << "\","
            << "\"size\":" << s.size << ","
            << "\"version\":" << s.version
            << "}";
        if (i + 1 < shards.size()) oss << ",";
    }

    oss << "]}";

    std::string canonical = oss.str();
    std::span<const uint8_t> data(
        reinterpret_cast<const uint8_t *>(canonical.data()),
        canonical.size());
    auto hash = crypto::SHA256::hash(data);
    manifest_hash = sha256_to_hex(hash);
}

bool ModelManifest::verify_hash() const {
    // 空 manifest_hash 视为"未设置"，返回 true（兼容旧 manifest）
    if (manifest_hash.empty()) return true;

    // 重新构造不含 manifest_hash 的 canonical JSON 并计算 sha256
    ModelManifest copy = *this;
    copy.manifest_hash.clear();
    copy.compute_hash();

    // 常量时间比较（manifest_hash 是 sha256 hex，64 字符）
    if (copy.manifest_hash.size() != manifest_hash.size()) return false;
    uint8_t diff = 0;
    for (std::size_t i = 0; i < manifest_hash.size(); ++i) {
        diff |= static_cast<uint8_t>(copy.manifest_hash[i] ^ manifest_hash[i]);
    }
    return diff == 0;
}

// =============================================================================
// shard 校验
// =============================================================================

ModelManifest::VerifyResult ModelManifest::verify_shards(
        std::string_view cache_dir) const {
    VerifyResult result;
    result.all_ok = true;

    namespace fs = std::filesystem;
    fs::path base(cache_dir);

    for (std::size_t i = 0; i < shards.size(); ++i) {
        const ShardEntry &shard = shards[i];
        fs::path file_path = base / shard.filename;

        // 1. 文件存在性
        if (!fs::exists(file_path)) {
            result.missing.push_back(i);
            result.all_ok = false;
            continue;
        }

        // 2. 文件大小
        std::uint64_t actual_size = 0;
        {
            std::error_code ec;
            auto fsize = fs::file_size(file_path, ec);
            if (ec) {
                result.missing.push_back(i);
                result.all_ok = false;
                continue;
            }
            actual_size = static_cast<std::uint64_t>(fsize);
        }
        if (shard.size != 0 && actual_size != shard.size) {
            result.size_mismatch.push_back(i);
            result.all_ok = false;
            continue;  // 大小不匹配，跳过 hash 计算（节省开销）
        }

        // 3. sha256 校验
        std::array<uint8_t, crypto::SHA256::kDigestSize> actual_hash{};
        std::uint64_t computed_size = 0;
        std::string file_str = file_path.string();
        if (!compute_file_sha256(file_str, actual_hash, computed_size)) {
            result.missing.push_back(i);
            result.all_ok = false;
            continue;
        }
        std::string actual_hex = sha256_to_hex(actual_hash);
        if (!shard.sha256_hex.empty() && actual_hex != shard.sha256_hex) {
            result.hash_mismatch.push_back(i);
            result.all_ok = false;
        }
    }

    return result;
}

// =============================================================================
// 便捷查询
// =============================================================================

const ShardEntry *ModelManifest::find_shard(std::uint32_t layer_index) const {
    for (const auto &s : shards) {
        if (s.layer_index == layer_index) return &s;
    }
    return nullptr;
}

std::uint64_t ModelManifest::total_size() const {
    std::uint64_t total = 0;
    for (const auto &s : shards) {
        total += s.size;
    }
    return total;
}

// =============================================================================
// v3.7.2 原子性辅助
// =============================================================================

bool ModelManifest::is_freshly_committed() const noexcept {
    // atomic_committed 必须为 true，且 schema_version 受支持
    // 当前受支持版本：v1（旧版，无 schema_version 字段，反序列化默认填充为 kLatestSchemaVersion）
    // 和 v2（v3.7.2 新版，含 atomic_committed 字段）
    if (!atomic_committed) return false;
    if (schema_version == 0) return false;  // 0 视为未设置/无效
    // 受支持版本白名单：1（兼容旧版默认）和 2（当前）
    if (schema_version != 1 && schema_version != kLatestSchemaVersion) {
        return false;
    }
    return true;
}

// =============================================================================
// manifest 文件读写
// =============================================================================

bool write_manifest_atomic(std::string_view path,
                            const ModelManifest &manifest) {
    // v3.7.2 原子性强化流程：
    // 1. 复制 manifest 副本，mark_writing()（atomic_committed=false）
    // 2. 重算 hash（含 atomic_committed=false）
    // 3. 写入临时文件（AtomicWriter 管理）
    // 4. mark_committed()（atomic_committed=true），重算 hash
    // 5. 覆盖临时文件内容，atomic rename 落盘
    // 读取端若发现 atomic_committed=false 则视为 stale（写入未完成）

    namespace fs = std::filesystem;
    fs::path target(path);
    fs::path parent = target.parent_path();
    if (parent.empty()) parent = fs::current_path();
    std::error_code ec;
    fs::create_directories(parent, ec);  // 确保父目录存在

    // 构造写入中的副本（atomic_committed=false）
    ModelManifest writing_copy = manifest;
    writing_copy.schema_version = ModelManifest::kLatestSchemaVersion;
    writing_copy.mark_writing();
    writing_copy.compute_hash();  // hash 包含 atomic_committed=false

    // 构造已提交的副本（atomic_committed=true）
    ModelManifest committed_copy = manifest;
    committed_copy.schema_version = ModelManifest::kLatestSchemaVersion;
    committed_copy.mark_committed();
    committed_copy.compute_hash();  // hash 包含 atomic_committed=true

    // 使用 AtomicWriter 管理临时目录
    util::AtomicWriter writer(parent.string(), ".manifest-tmp-");
    if (!writer.valid()) return false;

    // Step 1: 写入"写入中"版本的临时文件
    {
        std::string json_writing = writing_copy.to_json(true);
        std::span<const uint8_t> data(
            reinterpret_cast<const uint8_t *>(json_writing.data()),
            json_writing.size());
        std::string temp_filename = "manifest_writing.json";
        std::string temp_path = writer.temp_path(temp_filename);
        if (!util::atomic_write_file(temp_path, data)) {
            writer.discard();
            return false;
        }

        // Step 2: 改写临时文件为"已提交"版本（同一路径覆盖写入）
        std::string json_committed = committed_copy.to_json(true);
        std::span<const uint8_t> committed_data(
            reinterpret_cast<const uint8_t *>(json_committed.data()),
            json_committed.size());
        if (!util::atomic_write_file(temp_path, committed_data)) {
            writer.discard();
            return false;
        }

        // Step 3: 原子 rename 到目标路径
        if (!writer.commit(temp_filename, target.string())) {
            return false;  // writer 已 discard
        }
    }

    return true;
}

bool read_manifest(std::string_view path, ModelManifest &out) {
    std::ifstream ifs((std::string(path)), std::ios::binary);
    if (!ifs.is_open()) return false;

    std::ostringstream oss;
    oss << ifs.rdbuf();
    std::string content = oss.str();

    if (!ModelManifest::from_json(content, out)) return false;

    // v3.7.2: 检查原子提交标记
    // atomic_committed=false 表示写入未完成（stale cache），返回 false
    // 兼容旧版 manifest（无 atomic_committed 字段，反序列化默认填充为 true）
    if (!out.is_freshly_committed()) {
        // 标记为未提交，视为损坏
        return false;
    }
    return true;
}

bool read_and_verify_manifest(std::string_view path, ModelManifest &out) {
    if (!read_manifest(path, out)) return false;
    // read_manifest 已检查 atomic_committed
    return out.verify_hash();
}

// =============================================================================
// 为缓存目录构建 manifest
// =============================================================================

bool build_manifest_for_cache(std::string_view cache_dir,
                               std::string_view model_name,
                               std::string_view model_version,
                               std::uint32_t total_layers,
                               ModelManifest &out) {
    namespace fs = std::filesystem;
    fs::path base(cache_dir);
    std::error_code ec;
    if (!fs::exists(base, ec) || !fs::is_directory(base, ec)) {
        return false;
    }

    out = ModelManifest{};
    out.model_name = std::string(model_name);
    out.model_version = std::string(model_version);
    out.total_layers = total_layers;

    // 扫描 layer_XXXX.gguf 文件
    std::vector<std::pair<std::uint32_t, std::string>> found;
    for (const auto &entry : fs::directory_iterator(base, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        std::string fname = entry.path().filename().string();
        std::uint32_t idx = 0;
        if (parse_shard_filename(fname, idx)) {
            found.emplace_back(idx, fname);
        }
    }

    if (found.empty()) return false;

    // 按层索引升序排列
    std::sort(found.begin(), found.end());

    // 为每个 shard 计算 sha256 + size
    for (const auto &[idx, fname] : found) {
        ShardEntry shard;
        shard.layer_index = idx;
        shard.filename = fname;

        fs::path file_path = base / fname;
        std::string file_str = file_path.string();
        std::array<uint8_t, crypto::SHA256::kDigestSize> hash{};
        std::uint64_t size = 0;
        if (!compute_file_sha256(file_str, hash, size)) {
            return false;  // 文件读取失败
        }
        shard.sha256_hex = sha256_to_hex(hash);
        shard.size = size;
        shard.version = 1;

        out.shards.push_back(std::move(shard));
    }

    out.compute_hash();
    return true;
}

// =============================================================================
// shard 文件名辅助
// =============================================================================

std::string shard_filename(std::uint32_t layer_index) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "layer_%04u.gguf",
                  static_cast<unsigned>(layer_index));
    return std::string(buf);
}

bool parse_shard_filename(std::string_view filename,
                           std::uint32_t &out_index) {
    // 格式：layer_XXXX.gguf（XXXX 为 1-4 位十进制，前导零）
    if (filename.size() < 11) return false;  // "layer_.gguf" = 10，至少 1 位数字
    if (filename.substr(0, 6) != "layer_") return false;
    if (filename.substr(filename.size() - 5) != ".gguf") return false;

    std::string_view num_part = filename.substr(6, filename.size() - 11);
    if (num_part.empty() || num_part.size() > 4) return false;

    std::uint32_t v = 0;
    for (char c : num_part) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<std::uint32_t>(c - '0');
    }
    out_index = v;
    return true;
}

} // namespace linoh::collection
