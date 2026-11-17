// =============================================================================
// chunk_hash.cpp — v3.7.0 可靠性强化：sha256 chunk 校验实现
//
// 复用 linoh::crypto::SHA256（util/crypto.hpp），无新依赖
// =============================================================================

#include "linoh/crypto/chunk_hash.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>

namespace linoh::crypto {

// =============================================================================
// ChunkHasher
// =============================================================================

ChunkHasher::ChunkHasher(std::size_t chunk_size) noexcept {
    // clamp 到 [kMinChunkSize, kMaxChunkSize]
    if (chunk_size < kMinChunkSize) {
        chunk_size_ = kMinChunkSize;
    } else if (chunk_size > kMaxChunkSize) {
        chunk_size_ = kMaxChunkSize;
    } else {
        chunk_size_ = chunk_size;
    }
}

ChunkHashList ChunkHasher::compute(std::span<const uint8_t> data) const {
    ChunkHashList hashes;
    if (data.empty()) {
        // 空数据返回 1 个 chunk 的哈希（sha256 of empty）
        hashes.push_back(SHA256::hash({}));
        return hashes;
    }

    std::size_t offset = 0;
    while (offset < data.size()) {
        std::size_t end = (std::min)(offset + chunk_size_, data.size());
        std::span<const uint8_t> chunk(data.data() + offset, end - offset);
        hashes.push_back(SHA256::hash(chunk));
        offset = end;
    }
    return hashes;
}

ChunkHashList ChunkHasher::compute_from_file(std::string_view file_path,
                                               std::size_t *out_total_bytes) const {
    if (out_total_bytes) *out_total_bytes = 0;
    ChunkHashList hashes;

    std::ifstream ifs((std::string(file_path)), std::ios::binary);
    if (!ifs.is_open()) {
        return hashes;  // 文件打开失败返回空列表
    }

    std::vector<uint8_t> buffer(chunk_size_);
    std::size_t total = 0;
    bool any_read = false;

    while (true) {
        ifs.read(reinterpret_cast<char *>(buffer.data()),
                 static_cast<std::streamsize>(buffer.size()));
        std::streamsize n = ifs.gcount();
        if (n <= 0) break;
        any_read = true;
        std::span<const uint8_t> chunk(buffer.data(),
                                        static_cast<std::size_t>(n));
        hashes.push_back(SHA256::hash(chunk));
        total += static_cast<std::size_t>(n);
        if (n < static_cast<std::streamsize>(buffer.size())) break;  // EOF
    }

    if (!any_read) {
        // 空文件返回 1 个 chunk 的哈希（sha256 of empty）
        hashes.push_back(SHA256::hash({}));
    }

    if (out_total_bytes) *out_total_bytes = total;
    return hashes;
}

bool ChunkHasher::verify(std::span<const uint8_t> data,
                          const ChunkHashList &hashes) const {
    if (hashes.empty()) return false;

    if (data.empty()) {
        // 空数据要求 hashes.size()==1 且等于 sha256(empty)
        if (hashes.size() != 1) return false;
        ChunkHash expected = SHA256::hash({});
        return std::memcmp(hashes[0].data(), expected.data(),
                           SHA256::kDigestSize) == 0;
    }

    std::size_t expected_count =
        (data.size() + chunk_size_ - 1) / chunk_size_;
    if (hashes.size() != expected_count) return false;

    std::size_t offset = 0;
    for (std::size_t i = 0; i < hashes.size(); ++i) {
        std::size_t end = (std::min)(offset + chunk_size_, data.size());
        std::span<const uint8_t> chunk(data.data() + offset, end - offset);
        ChunkHash actual = SHA256::hash(chunk);
        if (std::memcmp(actual.data(), hashes[i].data(),
                        SHA256::kDigestSize) != 0) {
            return false;
        }
        offset = end;
    }
    return true;
}

bool ChunkHasher::verify_file(std::string_view file_path,
                               const ChunkHashList &hashes,
                               std::size_t expected_total_bytes) const {
    if (hashes.empty()) return false;

    std::ifstream ifs((std::string(file_path)), std::ios::binary);
    if (!ifs.is_open()) return false;

    // 先校验文件大小（若指定）
    if (expected_total_bytes > 0) {
        ifs.seekg(0, std::ios::end);
        std::streamsize size = ifs.tellg();
        ifs.seekg(0, std::ios::beg);
        if (static_cast<std::size_t>(size) != expected_total_bytes) {
            return false;
        }
    }

    std::vector<uint8_t> buffer(chunk_size_);
    std::size_t hash_idx = 0;
    bool any_read = false;

    while (hash_idx < hashes.size()) {
        ifs.read(reinterpret_cast<char *>(buffer.data()),
                 static_cast<std::streamsize>(buffer.size()));
        std::streamsize n = ifs.gcount();
        if (n <= 0) {
            // 文件比 hash 列表短
            if (!any_read && hash_idx == 0 && hashes.size() == 1) {
                // 空文件特殊处理
                ChunkHash expected = SHA256::hash({});
                return std::memcmp(hashes[0].data(), expected.data(),
                                   SHA256::kDigestSize) == 0;
            }
            return false;  // 文件读完但 hash 列表还有剩余
        }
        any_read = true;
        std::span<const uint8_t> chunk(buffer.data(),
                                        static_cast<std::size_t>(n));
        ChunkHash actual = SHA256::hash(chunk);
        if (std::memcmp(actual.data(), hashes[hash_idx].data(),
                        SHA256::kDigestSize) != 0) {
            return false;
        }
        ++hash_idx;
        if (n < static_cast<std::streamsize>(buffer.size())) {
            // 文件 EOF，检查 hash 列表是否也耗尽
            return hash_idx == hashes.size();
        }
    }

    // hash 列表耗尽，检查文件是否也读完
    ifs.read(reinterpret_cast<char *>(buffer.data()), 1);
    return ifs.gcount() == 0;
}

// =============================================================================
// Merkle Root
// =============================================================================

namespace {

/// 叶子节点哈希：sha256(0x00 || chunk_hash)
ChunkHash merkle_leaf_hash(const ChunkHash &chunk_hash) {
    std::array<uint8_t, 1 + SHA256::kDigestSize> buf;
    buf[0] = kMerkleLeafPrefix;
    std::memcpy(buf.data() + 1, chunk_hash.data(), SHA256::kDigestSize);
    return SHA256::hash(buf);
}

/// 中间节点哈希：sha256(0x01 || left || right)
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

ChunkHash compute_merkle_root(const ChunkHashList &hashes) {
    if (hashes.empty()) {
        ChunkHash zero{};
        return zero;  // 空列表返回全零
    }

    // 叶子层：每 chunk hash 转 leaf hash
    std::vector<ChunkHash> layer;
    layer.reserve(hashes.size());
    for (const auto &h : hashes) {
        layer.push_back(merkle_leaf_hash(h));
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

bool verify_merkle_root(std::span<const uint8_t> data,
                         std::size_t chunk_size,
                         const ChunkHash &expected_root) {
    ChunkHasher hasher(chunk_size);
    ChunkHashList hashes = hasher.compute(data);
    ChunkHash actual_root = compute_merkle_root(hashes);
    return std::memcmp(actual_root.data(), expected_root.data(),
                       SHA256::kDigestSize) == 0;
}

// =============================================================================
// 序列化辅助
// =============================================================================

std::vector<uint8_t> serialize_chunk_hash_list(const ChunkHashList &hashes) {
    std::vector<uint8_t> out;
    out.reserve(hashes.size() * SHA256::kDigestSize);
    for (const auto &h : hashes) {
        out.insert(out.end(), h.begin(), h.end());
    }
    return out;
}

ChunkHashList deserialize_chunk_hash_list(std::span<const uint8_t> data) {
    ChunkHashList hashes;
    if (data.size() % SHA256::kDigestSize != 0) {
        return hashes;  // 长度非 32 倍数返回空
    }
    std::size_t count = data.size() / SHA256::kDigestSize;
    hashes.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        ChunkHash h;
        std::memcpy(h.data(), data.data() + i * SHA256::kDigestSize,
                    SHA256::kDigestSize);
        hashes.push_back(h);
    }
    return hashes;
}

std::string to_hex(const ChunkHash &hash) {
    static const char *kHexChars = "0123456789abcdef";
    std::string out(SHA256::kDigestSize * 2, '0');
    for (std::size_t i = 0; i < SHA256::kDigestSize; ++i) {
        out[i * 2] = kHexChars[(hash[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHexChars[hash[i] & 0x0F];
    }
    return out;
}

bool from_hex(std::string_view hex, ChunkHash &out) {
    if (hex.size() != SHA256::kDigestSize * 2) return false;
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < SHA256::kDigestSize; ++i) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

} // namespace linoh::crypto
