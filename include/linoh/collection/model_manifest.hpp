#pragma once

// =============================================================================
// model_manifest.hpp — v3.7.1/v3.7.2 可靠性强化：内容寻址 manifest + 原子性
//
// 设计来源：sendme iroh-blobs Collection/HashSeq + Psyche GCS checkpoint
//   - 模型缓存用 manifest 记录每个 layer shard 的 sha256 + size + version
//   - 加载前校验：按 hash 精准定位缺失/损坏分片，仅重建该层（替代整包重建）
//   - manifest_hash 自身完整性校验（sha256 of canonical form，不含 manifest_hash 字段）
//
// v3.7.2 原子性强化：
//   - schema_version：manifest schema 版本号（区别于 model_version），用于格式升级兼容
//   - atomic_committed：原子提交标记，false 表示写入未完成（视为损坏），true 表示已原子提交
//   - write_manifest_atomic 升级为 AtomicWriter 集成：临时文件 atomic_committed=false →
//     commit 前 flip 为 true + 重算 hash → atomic rename 落盘
//   - read_manifest 检查 atomic_committed，false 则返回 false（stale cache 根治）
//
// 与 v3.7.0 的关系：
//   - shard hash 用 sha256（复用 linoh::crypto::SHA256，用户确认先用 sha256 兼容）
//   - manifest 文件原子写入复用 v3.7.0 的 util::atomic_write_file 和 AtomicWriter
//   - v3.8.4 预留：Merkle Root 完整性（用 v3.7.0 的 compute_merkle_root）
//
// 序列化格式：手写极简 JSON（字段固定、结构简单，无外部 JSON 库依赖）
//   - 人类可读，便于调试和跨语言互操作
//   - canonical 形式：字段顺序固定、无多余空白，用于 manifest_hash 计算
//
// 硬约束遵守：
//   - 缓存路径放 exe 同目录（硬约束 8，调用方保证 cache_dir 在 exe 同目录）
//   - 向后兼容：无 manifest 时回退旧行为（v3.6.1 不受影响）
//   - 旧版 manifest（无 schema_version/atomic_committed 字段）读取时按默认值兼容
// =============================================================================

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::collection {

// =============================================================================
// ShardEntry — 单个 layer shard 的内容寻址条目
// =============================================================================

struct ShardEntry {
    std::uint32_t layer_index = 0;   // 层索引（0-based）
    std::string filename;            // 文件名（如 "layer_0000.gguf"，不含路径）
    std::string sha256_hex;          // shard 的 sha256（64 字符小写十六进制）
    std::uint64_t size = 0;          // 文件大小（字节）
    std::uint32_t version = 1;       // 模型版本号（v3.7.2 原子性用，默认 1）
};

// =============================================================================
// ModelManifest — 模型缓存的 Collection manifest
// =============================================================================

struct ModelManifest {
    /// 当前 manifest schema 最新版本号
    /// v1: 初始版本（v3.7.1）
    /// v2: 添加 schema_version + atomic_committed 字段（v3.7.2）
    static constexpr std::uint32_t kLatestSchemaVersion = 2;

    std::string model_name;          // 模型名（如 "Qwen3.5-122B-A10B-Opus-Reasoning-Q4_K_XL"）
    std::string model_version;       // 模型版本（如 "v1.0"）
    std::uint32_t total_layers = 0;  // 总层数
    std::vector<ShardEntry> shards;  // shard 列表（按 layer_index 升序）
    std::string manifest_hash;       // manifest 自身 sha256（64 字符十六进制，compute_hash 填充）

    // v3.7.2 原子性字段
    std::uint32_t schema_version = kLatestSchemaVersion;  // manifest schema 版本号
    bool atomic_committed = true;  // 原子提交标记：false 表示写入未完成（视为损坏）

    // -------------------------------------------------------------------------
    // JSON 序列化 / 反序列化
    // -------------------------------------------------------------------------

    /// 序列化为 JSON 字符串（含 manifest_hash 字段，pretty=true 缩进可读）
    std::string to_json(bool pretty = false) const;

    /// 从 JSON 字符串反序列化
    /// @return true 成功；false JSON 格式错误或字段缺失
    static bool from_json(std::string_view json, ModelManifest &out);

    // -------------------------------------------------------------------------
    // manifest_hash 自身完整性
    // -------------------------------------------------------------------------

    /// 计算 manifest_hash 并填充（基于不含 manifest_hash 字段的 canonical JSON）
    /// @note 调用后 manifest_hash 字段被填充；重复调用幂等
    void compute_hash();

    /// 校验 manifest_hash 是否正确（基于当前字段值重新计算并比对）
    /// @return true 若 manifest_hash 为空（未设置）或与重算值一致；false 不一致
    /// @note 空 manifest_hash 视为"未设置"，返回 true（兼容旧 manifest）
    bool verify_hash() const;

    // -------------------------------------------------------------------------
    // shard 校验（加载前完整性检查）
    // -------------------------------------------------------------------------

    struct VerifyResult {
        bool all_ok = false;                  // 全部 shard 校验通过
        std::vector<std::size_t> missing;     // 缺失的 shard 索引（shards 数组下标）
        std::vector<std::size_t> hash_mismatch;  // sha256 不匹配的 shard 索引
        std::vector<std::size_t> size_mismatch;  // 文件大小不匹配的 shard 索引
    };

    /// 校验缓存目录下所有 shard 文件
    /// @param cache_dir 缓存目录（shard 文件位于 cache_dir/filename）
    /// @return VerifyResult，all_ok=true 表示所有 shard 完整可用
    /// @note 校验项：文件存在 + 大小匹配 + sha256 匹配
    VerifyResult verify_shards(std::string_view cache_dir) const;

    // -------------------------------------------------------------------------
    // 便捷查询
    // -------------------------------------------------------------------------

    /// 按 layer_index 查找 shard
    /// @return 找到返回指针，否则 nullptr
    const ShardEntry *find_shard(std::uint32_t layer_index) const;

    /// 所有 shard 的总字节数
    std::uint64_t total_size() const;

    /// shard 数量
    std::size_t shard_count() const noexcept { return shards.size(); }

    // -------------------------------------------------------------------------
    // v3.7.2 原子性辅助
    // -------------------------------------------------------------------------

    /// 检查 manifest 是否处于"已原子提交"状态
    /// @return true 若 atomic_committed=true 且 schema_version 受支持
    /// @note 读取后调用此方法判断 manifest 是否完整可用
    bool is_freshly_committed() const noexcept;

    /// 标记为"写入中"（atomic_committed=false），用于 write_manifest_atomic 内部
    void mark_writing() noexcept { atomic_committed = false; }

    /// 标记为"已提交"（atomic_committed=true），用于 write_manifest_atomic 内部
    /// @note 调用后应重新 compute_hash 以反映 atomic_committed 字段变化
    void mark_committed() noexcept { atomic_committed = true; }
};

// =============================================================================
// manifest 文件读写（原子写入用 v3.7.0 atomic_write_file）
// =============================================================================

/// 原子写入 manifest 文件（v3.7.2 增强：AtomicWriter + 原子标记机制）
/// @param path manifest 文件路径（如 "model_cache/Qwen.../model.manifest"）
/// @param manifest manifest 内容（manifest_hash 应已 compute_hash 填充）
/// @return true 成功；false 写入或 rename 失败
/// @note v3.7.2 流程：
///   1. 复制 manifest 副本，mark_writing()（atomic_committed=false）
///   2. 重算 hash（含 atomic_committed=false）
///   3. 写入临时文件（AtomicWriter 管理）
///   4. mark_committed()（atomic_committed=true），重算 hash
///   5. 覆盖临时文件内容，atomic rename 落盘
///   读取端若发现 atomic_committed=false 则视为 stale（写入未完成）
/// @note 调用前建议先 manifest.compute_hash() 确保 manifest_hash 已填充
bool write_manifest_atomic(std::string_view path, const ModelManifest &manifest);

/// 读取 manifest 文件（v3.7.2 增强：检查原子标记）
/// @param path manifest 文件路径
/// @param out 输出 manifest
/// @return true 成功且 atomic_committed=true；false 文件不存在/解析失败/未提交完成
/// @note v3.7.2：若 manifest 中 atomic_committed=false（写入未完成），返回 false
/// @note 读取后不会自动 verify_hash，调用方需显式校验
bool read_manifest(std::string_view path, ModelManifest &out);

/// 读取并校验 manifest（含 manifest_hash 自身完整性校验 + 原子标记检查）
/// @param path manifest 文件路径
/// @param out 输出 manifest
/// @return true 成功且 manifest_hash 校验通过且 atomic_committed=true；
///         false 文件不存在/解析失败/hash 不匹配/未提交完成
bool read_and_verify_manifest(std::string_view path, ModelManifest &out);

// =============================================================================
// 为指定缓存目录构建 manifest
// =============================================================================

/// 扫描缓存目录下所有 layer_XXXX.gguf 文件，计算 sha256 构建 manifest
/// @param cache_dir 缓存目录
/// @param model_name 模型名
/// @param model_version 模型版本
/// @param total_layers 总层数
/// @param out 输出 manifest（已 compute_hash 填充 manifest_hash）
/// @return true 成功；false 目录不存在或无 shard 文件
/// @note 文件名格式要求：layer_XXXX.gguf（XXXX 为 4 位十进制层索引，前导零）
bool build_manifest_for_cache(std::string_view cache_dir,
                               std::string_view model_name,
                               std::string_view model_version,
                               std::uint32_t total_layers,
                               ModelManifest &out);

// =============================================================================
// shard 文件命名约定辅助
// =============================================================================

/// 构造 shard 文件名（layer_XXXX.gguf）
/// @param layer_index 层索引
/// @return 文件名（如 "layer_0000.gguf"、"layer_0027.gguf"）
std::string shard_filename(std::uint32_t layer_index);

/// 从文件名解析层索引（layer_XXXX.gguf → XXXX）
/// @param filename 文件名
/// @param out_index 输出层索引
/// @return true 解析成功；false 格式不匹配
bool parse_shard_filename(std::string_view filename, std::uint32_t &out_index);

} // namespace linoh::collection
