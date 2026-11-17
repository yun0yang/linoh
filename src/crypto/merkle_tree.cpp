// =============================================================================
// merkle_tree.cpp — v3.8.4 TensorStream Merkle Root 完整性校验实现
//
// 复用 linoh::crypto::SHA256（util/crypto.hpp）+ kMerkleLeafPrefix/kMerkleIntermediatePrefix
// =============================================================================

#include "linoh/crypto/merkle_tree.hpp"

#include <cstring>

namespace linoh::crypto {

namespace {

/// 叶子节点哈希：sha256(0x00 || shard_data)
/// @note 与 chunk_hash.cpp 的 merkle_leaf_hash(ChunkHash) 不同：
///       - chunk_hash 叶子输入是 32 字节 chunk_hash（双重哈希）
///       - 本函数叶子输入是任意长度 shard_data（单次哈希）
ChunkHash merkle_leaf_hash_from_data(std::span<const uint8_t> shard_data) {
    // 构造 buffer: prefix(1) || shard_data(变长)
    std::vector<uint8_t> buf;
    buf.reserve(1 + shard_data.size());
    buf.push_back(kMerkleLeafPrefix);
    buf.insert(buf.end(), shard_data.begin(), shard_data.end());
    return SHA256::hash(buf);
}

/// 中间节点哈希：sha256(0x01 || left_hash || right_hash)
/// @note 与 chunk_hash.cpp 的 merkle_intermediate_hash 完全一致（复用逻辑）
ChunkHash merkle_intermediate_hash(const ChunkHash &left,
                                     const ChunkHash &right) {
    std::array<uint8_t, 1 + SHA256::kDigestSize * 2> buf;
    buf[0] = kMerkleIntermediatePrefix;
    std::memcpy(buf.data() + 1, left.data(), SHA256::kDigestSize);
    std::memcpy(buf.data() + 1 + SHA256::kDigestSize, right.data(),
                SHA256::kDigestSize);
    return SHA256::hash(buf);
}

} // namespace

ChunkHash compute_merkle_root_from_shards(
    const std::vector<std::span<const uint8_t>> &shards) {
    if (shards.empty()) {
        return zero_root();  // 空列表返回全零
    }

    // 叶子层：每 shard_data 转 leaf hash
    std::vector<ChunkHash> layer;
    layer.reserve(shards.size());
    for (const auto &shard : shards) {
        layer.push_back(merkle_leaf_hash_from_data(shard));
    }

    // 逐层归并直到 root
    while (layer.size() > 1) {
        std::vector<ChunkHash> next;
        next.reserve((layer.size() + 1) / 2);
        for (std::size_t i = 0; i < layer.size(); i += 2) {
            if (i + 1 < layer.size()) {
                next.push_back(merkle_intermediate_hash(layer[i], layer[i + 1]));
            } else {
                // 奇数节点：与自身组合（不补零，避免引入虚假数据）
                next.push_back(merkle_intermediate_hash(layer[i], layer[i]));
            }
        }
        layer = std::move(next);
    }

    return layer[0];
}

bool verify_tensor_merkle_root(
    const std::vector<std::span<const uint8_t>> &shards,
    const ChunkHash &expected_root) {
    // 空 shards + 全零 root → 向后兼容（旧节点无 merkle_root 场景）
    if (shards.empty() && is_zero_root(expected_root)) {
        return true;
    }
    // 空 shards + 非零 root → 校验失败
    if (shards.empty()) {
        return false;
    }

    ChunkHash actual_root = compute_merkle_root_from_shards(shards);
    return std::memcmp(actual_root.data(), expected_root.data(),
                       SHA256::kDigestSize) == 0;
}

bool verify_tensor_merkle_root(
    const std::vector<std::vector<uint8_t>> &shards,
    const ChunkHash &expected_root) {
    // 转换为 span 列表复用核心实现
    std::vector<std::span<const uint8_t>> spans;
    spans.reserve(shards.size());
    for (const auto &shard : shards) {
        spans.emplace_back(shard.data(), shard.size());
    }
    return verify_tensor_merkle_root(spans, expected_root);
}

bool is_zero_root(const ChunkHash &root) noexcept {
    for (std::size_t i = 0; i < SHA256::kDigestSize; ++i) {
        if (root[i] != 0) return false;
    }
    return true;
}

ChunkHash zero_root() noexcept {
    ChunkHash zero{};
    return zero;
}

} // namespace linoh::crypto
