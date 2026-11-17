#pragma once

// =============================================================================
// chunk_hash.hpp — v3.7.0 可靠性强化：sha256 chunk 校验 + Merkle Root 完整性
//
// 设计来源：sendme iroh-blobs verified streaming + Psyche merkle_tree
//   - 数据按固定 chunk 大小切分，每 chunk 计算 sha256（外置 outboard 元数据）
//   - chunk hash 列表组成 Merkle Tree，root hash 作为整体完整性指纹
//   - 叶子节点 sha256(0x00 || chunk_data)，中间节点 sha256(0x01 || left || right)
//     （前缀防第二原像，参考 Psyche shared/core/src/merkle_tree.rs）
//
// v3.7.0 范围：chunk 级 sha256 校验（替代 BLAKE3，后续 v3.7.x+ 可升级）
// v3.8.4 预留：Merkle Root 完整性校验接口（TensorStream 重组后校验）
//
// 复用现有 linoh::crypto::SHA256（util/crypto.hpp），无新依赖
// =============================================================================

#include <linoh/util/crypto.hpp>

#include <array>
#include <cstdint>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::crypto {

// =============================================================================
// 类型别名
// =============================================================================

/// 单个 chunk 的 sha256 哈希（32 字节）
using ChunkHash = std::array<uint8_t, SHA256::kDigestSize>;

/// chunk hash 列表（按 chunk 顺序排列）
using ChunkHashList = std::vector<ChunkHash>;

// =============================================================================
// ChunkHasher — chunk 级 sha256 计算 + 校验
// =============================================================================

class ChunkHasher {
public:
    /// 默认 chunk 大小：16KiB
    /// （参考 iroh-blobs 用 1KiB，但 GPU tensor 块大，16KiB 减少 16x 元数据开销）
    static constexpr std::size_t kDefaultChunkSize = 16 * 1024;

    /// 最小 chunk 大小：1KiB（防止误配为 0 或过小）
    static constexpr std::size_t kMinChunkSize = 1024;

    /// 最大 chunk 大小：1MiB（防止 chunk 过大导致内存压力）
    static constexpr std::size_t kMaxChunkSize = 1024 * 1024;

    /// 构造指定 chunk 大小的 hasher
    /// @param chunk_size chunk 大小（字节），会被 clamp 到 [kMinChunkSize, kMaxChunkSize]
    explicit ChunkHasher(std::size_t chunk_size = kDefaultChunkSize) noexcept;

    /// 返回当前 chunk 大小
    std::size_t chunk_size() const noexcept { return chunk_size_; }

    /// 计算数据的 chunk hash 列表
    /// @param data 输入数据（按 chunk_size 切分，末尾不足一个 chunk 照常哈希）
    /// @return chunk hash 列表（长度 = ceil(data.size() / chunk_size)，空数据返回 1 个 chunk 的哈希）
    ChunkHashList compute(std::span<const uint8_t> data) const;

    /// 计算文件的 chunk hash 列表（流式读取，避免大文件内存爆炸）
    /// @param file_path 文件路径
    /// @param[out] out_total_bytes 输出文件总字节数（可选，nullptr 忽略）
    /// @return chunk hash 列表；文件打开失败返回空列表
    ChunkHashList compute_from_file(std::string_view file_path,
                                     std::size_t *out_total_bytes = nullptr) const;

    /// 校验数据与 chunk hash 列表是否一致
    /// @param data 输入数据
    /// @param hashes 期望的 chunk hash 列表
    /// @return true 若数据按 chunk_size 切分后每 chunk sha256 与 hashes 对应项一致
    /// @note 长度校验：hashes.size() 必须等于 ceil(data.size() / chunk_size)
    ///       （空数据要求 hashes.size()==1，与 compute 一致）
    bool verify(std::span<const uint8_t> data,
                const ChunkHashList &hashes) const;

    /// 校验文件与 chunk hash 列表是否一致（流式读取）
    /// @param file_path 文件路径
    /// @param hashes 期望的 chunk hash 列表
    /// @param expected_total_bytes 期望的文件总字节数（0 表示不校验大小）
    /// @return true 若文件总大小匹配且每 chunk sha256 与 hashes 对应项一致
    bool verify_file(std::string_view file_path,
                     const ChunkHashList &hashes,
                     std::size_t expected_total_bytes = 0) const;

private:
    std::size_t chunk_size_;
};

// =============================================================================
// Merkle Root — 整体完整性指纹（v3.8.4 TensorStream 预留接口）
// =============================================================================

/// Merkle Tree 叶子节点前缀（防第二原像，参考 Psyche merkle_tree.rs）
///   叶子 = sha256(0x00 || chunk_hash)
///   中间 = sha256(0x01 || left_hash || right_hash)
constexpr uint8_t kMerkleLeafPrefix = 0x00;
constexpr uint8_t kMerkleIntermediatePrefix = 0x01;

/// 从 chunk hash 列表计算 Merkle Root
/// @param hashes chunk hash 列表（非空）
/// @return Merkle Root（32 字节）；空列表返回全零哈希
/// @note Merkle Tree 构造规则：
///   1. 叶子层：每 chunk hash 再哈希一次 sha256(0x00 || chunk_hash) 作为叶子节点
///   2. 中间层：相邻两节点组合 sha256(0x01 || left || right)，奇数节点补自身
///   3. 重复直到只剩一个节点（root）
///   4. 单 chunk 时 root = sha256(0x00 || chunk_hash)（即叶子层唯一节点）
ChunkHash compute_merkle_root(const ChunkHashList &hashes);

/// 校验数据 + chunk hash 列表 + Merkle Root 三者一致性
/// @param data 输入数据
/// @param chunk_size 计算 chunk hash 时的 chunk 大小
/// @param expected_root 期望的 Merkle Root
/// @return true 若 data 的 chunk hash 列表的 Merkle Root 等于 expected_root
bool verify_merkle_root(std::span<const uint8_t> data,
                         std::size_t chunk_size,
                         const ChunkHash &expected_root);

// =============================================================================
// 序列化辅助 — chunk hash 列表与字节数组互转（用于 manifest 存储）
// =============================================================================

/// chunk hash 列表序列化为拼接字节流（每 hash 32 字节，总长度 = 32 * count）
/// @param hashes chunk hash 列表
/// @return 拼接字节流
std::vector<uint8_t> serialize_chunk_hash_list(const ChunkHashList &hashes);

/// 从拼接字节流反序列化 chunk hash 列表
/// @param data 字节流（长度必须是 32 的倍数）
/// @return chunk hash 列表；长度非 32 倍数返回空列表
ChunkHashList deserialize_chunk_hash_list(std::span<const uint8_t> data);

/// chunk hash 转十六进制字符串（64 字符，小写）
std::string to_hex(const ChunkHash &hash);

/// 十六进制字符串转 chunk hash（64 字符 → 32 字节）
/// @return 解析成功返回 true；长度非 64 或非 hex 字符返回 false
bool from_hex(std::string_view hex, ChunkHash &out);

} // namespace linoh::crypto
