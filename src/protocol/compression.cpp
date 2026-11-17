// compression.cpp — V3.4 按需压缩实现（zstd）+ O1 协议字典压缩
//
// zstd 压缩/解压基于 vendored zstd 1.5.6（third_party/zstd/）。
// compress：ZSTD_compressBound 估算上界 → ZSTD_compress 压缩 → resize 实际大小
// decompress：ZSTD_getFrameContentSize 从帧头解析原始大小 → ZSTD_decompress 解压
//
// O1（cluster 编码层优化方案）：进程级字典注册表 + 字典压缩/解压 +
// 自动压缩开关。wire 格式 [dict_id: 1B][zstd frame]。

#include "linoh/protocol/compression.hpp"

#include <zstd.h>  // vendored zstd 1.5.6（build_all.bat /Ithird_party\zstd）
#include <xxhash.h>      // vendored xxhash（linoh_zstd 已含 common/xxhash.c）

#include <cstdio>

#include <map>
#include <mutex>

namespace linoh::protocol {

// ============================================================================
// 内部：zstd 压缩/解压
// ============================================================================

static std::vector<std::uint8_t> zstd_compress(
    std::span<const std::uint8_t> in, int level) {
    if (in.empty()) return {};
    if (level <= 0) level = kDefaultZstdLevel;
    if (level > 22) level = 22;  // zstd 最高级别

    size_t bound = ZSTD_compressBound(in.size());
    if (ZSTD_isError(bound)) return {};

    std::vector<std::uint8_t> out(bound);
    size_t r = ZSTD_compress(out.data(), bound, in.data(), in.size(), level);
    if (ZSTD_isError(r)) return {};

    out.resize(r);
    return out;
}

static std::vector<std::uint8_t> zstd_decompress(
    std::span<const std::uint8_t> in, std::size_t expected_size) {
    if (in.empty()) return {};

    // 未提供 expected_size 时从 zstd 帧头解析原始大小
    if (expected_size == 0) {
        unsigned long long cs = ZSTD_getFrameContentSize(in.data(), in.size());
        if (cs == ZSTD_CONTENTSIZE_UNKNOWN || cs == ZSTD_CONTENTSIZE_ERROR) {
            return {};
        }
        expected_size = static_cast<std::size_t>(cs);
    }
    if (expected_size == 0) return {};  // 原始内容为空

    std::vector<std::uint8_t> out(expected_size);
    size_t r = ZSTD_decompress(out.data(), expected_size, in.data(), in.size());
    if (ZSTD_isError(r)) return {};

    out.resize(r);
    return out;
}

// ============================================================================
// O1: 进程级字典注册表（线程安全）
// ============================================================================

namespace {

struct DictEntry {
    std::vector<std::uint8_t> raw;  // 原始字典内容（供 DDict 构建）
};

std::mutex g_dict_mu;
std::map<std::uint8_t, DictEntry> g_dicts;
std::uint8_t g_default_dict_id = 0;
bool g_auto_compress = false;       // 默认 off，部署侧灰度开启
int  g_auto_level = 3;

// 每线程字典压缩上下文不可跨线程复用 CDict？ZSTD_CDict 线程安全（创建后只读），
// 但 CCtx 非线程安全 —— 每次调用用栈上一次性创建（compress Bound 内开销可接受，
// 字典场景的消息频率远低于 per-token 量级）。
// DDict 同理只读安全。为避免静态生命周期与 zstd 版本清理顺序问题，
// CDict/DDict 按调用创建销毁（compress_usingDict 直接传 raw dict 亦可，
// zstd 内部会构建 entropy tables —— 传 raw dict 的简单实现）。

}  // namespace

bool load_protocol_dict(std::uint8_t dict_id,
                        std::span<const std::uint8_t> dict) {
    if (dict.empty() || dict.size() > 1024 * 1024) return false;  // 上限 1MB
    std::lock_guard<std::mutex> lk(g_dict_mu);
    DictEntry e;
    e.raw.assign(dict.begin(), dict.end());
    g_dicts[dict_id] = std::move(e);
    g_default_dict_id = dict_id;
    return true;
}

void clear_protocol_dicts() {
    std::lock_guard<std::mutex> lk(g_dict_mu);
    g_dicts.clear();
    g_default_dict_id = 0;
}

bool has_protocol_dict(std::uint8_t dict_id) {
    std::lock_guard<std::mutex> lk(g_dict_mu);
    return g_dicts.count(dict_id) != 0;
}

bool has_any_protocol_dict() noexcept {
    // 无锁读 default id 再确认（map 竞态下最多误判一次，调用方回退无字典压缩）
    return g_default_dict_id != 0;
}

std::uint8_t default_dict_id() noexcept {
    return g_default_dict_id;
}

std::vector<std::uint8_t> compress_payload_dict(
    std::span<const std::uint8_t> in, int level, std::uint8_t dict_id) {
    if (in.empty()) return {};

    std::vector<std::uint8_t> dict_raw;
    {
        std::lock_guard<std::mutex> lk(g_dict_mu);
        auto it = g_dicts.find(dict_id);
        if (it == g_dicts.end()) return {};
        dict_raw = it->second.raw;  // 拷贝出锁外使用
    }

    if (level <= 0) level = kDefaultZstdLevel;
    if (level > 22) level = 22;

    size_t bound = ZSTD_compressBound(in.size());
    if (ZSTD_isError(bound)) return {};

    std::vector<std::uint8_t> out(1 + bound);  // [dict_id: 1B][frame]
    out[0] = dict_id;

    ZSTD_CCtx *cctx = ZSTD_createCCtx();
    if (!cctx) return {};
    size_t r = ZSTD_compress_usingDict(
        cctx, out.data() + 1, bound, in.data(), in.size(),
        dict_raw.data(), dict_raw.size(), level);
    ZSTD_freeCCtx(cctx);
    if (ZSTD_isError(r)) return {};

    out.resize(1 + r);
    return out;
}

std::vector<std::uint8_t> decompress_payload_dict(
    std::span<const std::uint8_t> in) {
    if (in.size() <= 1) return {};

    const std::uint8_t dict_id = in[0];
    std::vector<std::uint8_t> dict_raw;
    {
        std::lock_guard<std::mutex> lk(g_dict_mu);
        auto it = g_dicts.find(dict_id);
        if (it == g_dicts.end()) return {};  // 字典未加载
        dict_raw = it->second.raw;
    }

    std::span<const std::uint8_t> frame(in.data() + 1, in.size() - 1);
    unsigned long long cs = ZSTD_getFrameContentSize(frame.data(), frame.size());
    if (cs == ZSTD_CONTENTSIZE_UNKNOWN || cs == ZSTD_CONTENTSIZE_ERROR) {
        return {};
    }
    std::size_t expected = static_cast<std::size_t>(cs);
    if (expected == 0) return {};
    if (expected > 64u * 1024 * 1024) return {};  // 64MB 上限（防恶意帧头）

    std::vector<std::uint8_t> out(expected);
    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    if (!dctx) return {};
    size_t r = ZSTD_decompress_usingDict(
        dctx, out.data(), expected, frame.data(), frame.size(),
        dict_raw.data(), dict_raw.size());
    ZSTD_freeDCtx(dctx);
    if (ZSTD_isError(r)) return {};

    out.resize(r);
    return out;
}

bool load_protocol_dict_file(const char *path, std::uint8_t dict_id) {
    if (!path) return false;
    std::FILE *f = std::fopen(path, "rb");
    if (!f) return false;
    std::vector<std::uint8_t> data;
    std::uint8_t chunk[65536];
    size_t n;
    while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0) {
        data.insert(data.end(), chunk, chunk + n);
        if (data.size() > 1024 * 1024) {  // 与 load_protocol_dict 上限一致
            std::fclose(f);
            return false;
        }
    }
    std::fclose(f);
    if (data.empty()) return false;
    return load_protocol_dict(dict_id,
                              std::span<const std::uint8_t>(data.data(), data.size()));
}

ProtocolDictInfo protocol_dict_info(std::uint8_t dict_id) {
    ProtocolDictInfo info;
    info.dict_id = dict_id;
    std::lock_guard<std::mutex> lk(g_dict_mu);
    auto it = g_dicts.find(dict_id);
    if (it == g_dicts.end()) return info;
    info.loaded = true;
    info.size = it->second.raw.size();
    info.xxh64 = XXH64(it->second.raw.data(), it->second.raw.size(), 0);
    return info;
}

void set_auto_compress(bool on, int level) {
    std::lock_guard<std::mutex> lk(g_dict_mu);
    g_auto_compress = on;
    if (level >= 1 && level <= 22) g_auto_level = level;
}

bool auto_compress_enabled() noexcept {
    return g_auto_compress;
}

// ============================================================================
// 公开接口
// ============================================================================

std::vector<std::uint8_t> compress_payload(
    std::span<const std::uint8_t> in,
    CompressionAlgo algo,
    int level) {
    switch (algo) {
        case CompressionAlgo::None:
            // 原样返回（拷贝）
            return std::vector<std::uint8_t>(in.begin(), in.end());
        case CompressionAlgo::Zstd:
            return zstd_compress(in, level);
        case CompressionAlgo::Gzip:
            // V3.4 暂未实现 gzip（需引入 miniz/zlib）
            return {};
    }
    return {};
}

std::vector<std::uint8_t> decompress_payload(
    std::span<const std::uint8_t> in,
    CompressionAlgo algo,
    std::size_t expected_size) {
    switch (algo) {
        case CompressionAlgo::None:
            // 原样返回（拷贝）
            return std::vector<std::uint8_t>(in.begin(), in.end());
        case CompressionAlgo::Zstd:
            return zstd_decompress(in, expected_size);
        case CompressionAlgo::Gzip:
            // V3.4 暂未实现 gzip
            return {};
    }
    return {};
}

CompressionAlgo recommend_compression(
    std::size_t payload_size, MethodId method) {
    // 小消息区间：流式压缩为负收益（实测 43B→52B 膨胀）
    constexpr std::size_t kMinCompressSize = 300;

    // Heartbeat 永不压缩（小消息，高频，压缩开销大于收益）
    if (method == MethodId::Heartbeat) {
        return CompressionAlgo::None;
    }

    // Tensor 分片族 / 可用性位图 / 认证帧：与分片缓冲、hash 公告、
    // 挑战-签名语义强耦合，不参与透明压缩
    switch (method) {
        case MethodId::TensorShard:
        case MethodId::TensorShardAck:
        case MethodId::TensorCancel:
        case MethodId::ShardHashAnnounce:
        case MethodId::Observe:
        case MethodId::AuthChallenge:
        case MethodId::AuthResponse:
            return CompressionAlgo::None;
        default:
            break;
    }

    if (payload_size < kMinCompressSize) {
        return CompressionAlgo::None;
    }

    // ForwardPP / ResultPP：hidden_state / 推理结果，1KB+ 压缩
    // （浮点尾数熵高，收益有限；保持既有阈值，行为不漂移）
    if (method == MethodId::ForwardPP || method == MethodId::ResultPP) {
        return payload_size >= 1024 ? CompressionAlgo::Zstd : CompressionAlgo::None;
    }

    // 结构化控制面方法：300B+ 即压缩（1–16KB 是字典压缩主战场）。
    // 这些方法的 payload 为 JSON/结构化二进制（schema 字段名、URL 前缀
    // 等跨消息先验丰富，实测字典压缩 -92%）
    switch (method) {
        case MethodId::Join:
        case MethodId::JoinAck:
        case MethodId::Leave:
        case MethodId::LoadModel:
        case MethodId::LoadModelAck:
        case MethodId::Drain:
        case MethodId::StateChange:
        case MethodId::ErrorReport:
        case MethodId::CancelInference:
        case MethodId::CrossDomainDigest:
        case MethodId::CrossDomainDigestReq:
        case MethodId::CrossDomainAddrHint:
        case MethodId::CrossDomainAddrQuery:
        case MethodId::CrossDomainAddrResp:
        case MethodId::AddrInfoAnnounce:
        case MethodId::ProgressReport:
        case MethodId::ReturnAddrProbe:
        case MethodId::ReturnAddrAck:
        case MethodId::CapabilitiesProbe:
        case MethodId::CapabilitiesAck:
            return CompressionAlgo::Zstd;
        default:
            break;
    }

    // 其他/未知方法默认 16KB+ 压缩（与旧规则一致）
    return payload_size >= 16 * 1024 ? CompressionAlgo::Zstd : CompressionAlgo::None;
}

}  // namespace linoh::protocol
