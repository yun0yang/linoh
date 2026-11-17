#pragma once

// =============================================================================
// merkle_tree.hpp — v3.8.4 TensorStream Merkle Root 完整性校验
//
// 设计来源：Psyche shared/core/src/merkle_tree.rs
//   - 叶子节点：sha256(0x00 || shard_data)        （单次哈希，直接对原始 shard 数据）
//   - 中间节点：sha256(0x01 || left_hash || right_hash)
//   - 奇数节点：与自身组合（不补零，避免引入虚假数据）
//   - 前缀 0x00/0x01 防第二原像攻击
//
// 与 v3.7.0 chunk_hash.hpp 的关系：
//   - chunk_hash.compute_merkle_root(ChunkHashList) 叶子 = sha256(0x00||sha256(chunk))
//     用于 model_cache 文件 chunk 级校验（双重哈希，BLAKE3 verified streaming 模式）
//   - merkle_tree.compute_merkle_root_from_shards(shards) 叶子 = sha256(0x00||shard_data)
//     用于 TensorStream shard 级校验（单次哈希，Psyche merkle_tree.rs 模式）
//   - 两者语义不同，互不干扰，各自独立
//
// v3.8.4 范围：
//   1. 从 shard 数据列表计算 Merkle Root
//   2. 校验重组后的 tensor 数据完整性
//   3. TensorReassembler.maybe_complete() hook 集成（仅末节点 is_last=true 校验）
//
// 复用现有 linoh::crypto::SHA256（util/crypto.hpp）+ kMerkleLeafPrefix/kMerkleIntermediatePrefix
// =============================================================================

#include "linoh/crypto/chunk_hash.hpp"  // ChunkHash, kMerkleLeafPrefix, kMerkleIntermediatePrefix, SHA256

#include <cstdint>
#include <span>
#include <vector>

namespace linoh::crypto {

// =============================================================================
// TensorStream Merkle Tree — shard 级完整性校验
// =============================================================================

/// 从 shard 数据列表计算 Merkle Root（Psyche merkle_tree.rs 模式）
///
/// @param shards 按 shard_idx 排序的 shard 数据列表（每个 span 为一个 shard 的原始字节）
/// @return Merkle Root（32 字节）；空列表返回全零哈希
///
/// @note Merkle Tree 构造规则：
///   1. 叶子层：sha256(0x00 || shard_data)（单次哈希，直接对原始 shard 数据）
///   2. 中间层：sha256(0x01 || left_hash || right_hash)，奇数节点与自身组合
///   3. 重复直到只剩一个节点（root）
///   4. 单 shard 时 root = sha256(0x00 || shard_data)（即叶子层唯一节点）
///
/// @note 与 chunk_hash.compute_merkle_root(ChunkHashList) 的区别：
///   - chunk_hash 叶子 = sha256(0x00 || sha256(chunk))（双重哈希）
///   - 本函数  叶子 = sha256(0x00 || shard_data)  （单次哈希）
///   - 两者不可混用，root 值不同
ChunkHash compute_merkle_root_from_shards(
    const std::vector<std::span<const uint8_t>> &shards);

/// 校验重组后的 tensor 数据完整性
///
/// @param shards 按 shard_idx 排序的 shard 数据列表
/// @param expected_root 期望的 Merkle Root（来自 TensorMeta.merkle_root）
/// @return true 若 shards 的 Merkle Root 等于 expected_root
///
/// @note 调用方需确保 shards 已按 shard_idx 排序且数量完整（total_shards 个）。
///       空 shards 列表 + expected_root 全零 → 返回 true（向后兼容无 merkle_root 场景）
bool verify_tensor_merkle_root(
    const std::vector<std::span<const uint8_t>> &shards,
    const ChunkHash &expected_root);

/// 便捷重载：接受 vector<vector<uint8_t>>（TensorReassembler 内部存储格式）
bool verify_tensor_merkle_root(
    const std::vector<std::vector<uint8_t>> &shards,
    const ChunkHash &expected_root);

/// 判断 Merkle Root 是否为"全零"（即未设置 merkle_root 的兼容场景）
/// @return true 若 32 字节全为零
bool is_zero_root(const ChunkHash &root) noexcept;

/// 生成全零 Merkle Root（用于不支持 merkle_root 的旧节点兼容场景）
ChunkHash zero_root() noexcept;

} // namespace linoh::crypto
