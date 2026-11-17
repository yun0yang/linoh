// =============================================================================
// test_merkle_tree.cpp — v3.8.4 TensorStream Merkle Root 完整性校验单元测试
//
// 覆盖场景：
//   1. 单 shard tensor
//   2. 偶数 shard（2/4/8）
//   3. 奇数 shard（3/5/7）
//   4. 空 tensor（空 shards 列表）
//   5. tampered shard_data（篡改数据）
//   6. tampered merkle_root（篡改 root）
//   7. shard 顺序一致性
//   8. 与 chunk_hash.compute_merkle_root 互斥性验证
//   9. zero_root / is_zero_root
//  10. 大 tensor（模拟 1GB 分片）
//  11. vector<vector<uint8_t>> 便捷重载
//  12. 确定性验证（相同输入相同 root）
// =============================================================================

#include "linoh/crypto/merkle_tree.hpp"
#include "linoh/crypto/chunk_hash.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

using namespace linoh::crypto;

namespace {

/// 生成指定大小的确定性数据（按位置填充）
std::vector<uint8_t> make_data(std::size_t size, uint8_t seed = 0) {
    std::vector<uint8_t> data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
    return data;
}

/// 将 vector<vector<uint8_t>> 转为 vector<span<const uint8_t>>
/// @note 调用方必须保证 shards 的生命周期长于返回的 spans
std::vector<std::span<const uint8_t>> to_spans(
    const std::vector<std::vector<uint8_t>> &shards) {
    std::vector<std::span<const uint8_t>> spans;
    spans.reserve(shards.size());
    for (const auto &s : shards) {
        spans.emplace_back(s.data(), s.size());
    }
    return spans;
}

int test_count = 0;
int test_passed = 0;

#define RUN_TEST(name)                                                        \
    do {                                                                      \
        ++test_count;                                                         \
        std::cout << "  [test] " #name " ... ";                               \
        name();                                                               \
        ++test_passed;                                                        \
        std::cout << "OK\n";                                                  \
    } while (0)

} // namespace

// =============================================================================
// 1. 单 shard tensor
// =============================================================================

void test_single_shard_root() {
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(make_data(1024, 0x42));
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    assert(!is_zero_root(root));

    // 单 shard: root = sha256(0x00 || shard_data)
    std::vector<uint8_t> expected_buf;
    expected_buf.push_back(kMerkleLeafPrefix);
    expected_buf.insert(expected_buf.end(), shards[0].begin(), shards[0].end());
    ChunkHash expected = SHA256::hash(expected_buf);
    assert(std::memcmp(root.data(), expected.data(), SHA256::kDigestSize) == 0);
}

void test_single_shard_verify() {
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(make_data(2048, 0x11));
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    assert(verify_tensor_merkle_root(spans, root));
}

void test_single_empty_shard() {
    // 单个空 shard（0 字节数据）
    std::vector<std::vector<uint8_t>> shards;
    shards.emplace_back();  // 空 vector
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    // root = sha256(0x00) — 单个空数据 shard 的叶子哈希
    std::vector<uint8_t> expected_buf;
    expected_buf.push_back(kMerkleLeafPrefix);
    ChunkHash expected = SHA256::hash(expected_buf);
    assert(std::memcmp(root.data(), expected.data(), SHA256::kDigestSize) == 0);
    assert(verify_tensor_merkle_root(spans, root));
}

// =============================================================================
// 2. 偶数 shard（2/4/8）
// =============================================================================

void test_two_shards() {
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(make_data(64, 0x01));
    shards.push_back(make_data(64, 0x02));
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    assert(!is_zero_root(root));
    assert(verify_tensor_merkle_root(spans, root));
}

void test_four_shards() {
    std::vector<std::vector<uint8_t>> shards;
    for (int i = 0; i < 4; ++i) {
        shards.push_back(make_data(128, static_cast<uint8_t>(i)));
    }
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    assert(verify_tensor_merkle_root(spans, root));

    // 验证手动计算：layer0 = [leaf(s0), leaf(s1), leaf(s2), leaf(s3)]
    // layer1 = [inter(leaf0,leaf1), inter(leaf2,leaf3)]
    // root = inter(layer1[0], layer1[1])
    auto leaf = [](std::span<const uint8_t> d) {
        std::vector<uint8_t> buf;
        buf.push_back(kMerkleLeafPrefix);
        buf.insert(buf.end(), d.begin(), d.end());
        return SHA256::hash(buf);
    };
    auto inter = [](const ChunkHash &l, const ChunkHash &r) {
        std::array<uint8_t, 1 + 64> buf;
        buf[0] = kMerkleIntermediatePrefix;
        std::memcpy(buf.data() + 1, l.data(), 32);
        std::memcpy(buf.data() + 33, r.data(), 32);
        return SHA256::hash(buf);
    };
    ChunkHash l0 = leaf(shards[0]), l1 = leaf(shards[1]),
             l2 = leaf(shards[2]), l3 = leaf(shards[3]);
    ChunkHash i0 = inter(l0, l1), i1 = inter(l2, l3);
    ChunkHash expected_root = inter(i0, i1);
    assert(std::memcmp(root.data(), expected_root.data(), 32) == 0);
}

void test_eight_shards() {
    std::vector<std::vector<uint8_t>> shards;
    for (int i = 0; i < 8; ++i) {
        shards.push_back(make_data(256, static_cast<uint8_t>(i * 10)));
    }
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    assert(verify_tensor_merkle_root(spans, root));
}

// =============================================================================
// 3. 奇数 shard（3/5/7）
// =============================================================================

void test_three_shards() {
    // 3 shards: 奇数节点补自身
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(make_data(100, 0xA));
    shards.push_back(make_data(100, 0xB));
    shards.push_back(make_data(100, 0xC));
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    assert(verify_tensor_merkle_root(spans, root));

    // 验证：layer0 = [leaf0, leaf1, leaf2]
    // layer1 = [inter(leaf0,leaf1), inter(leaf2,leaf2)]  ← 奇数节点补自身
    // root = inter(layer1[0], layer1[1])
    auto leaf = [](std::span<const uint8_t> d) {
        std::vector<uint8_t> buf;
        buf.push_back(kMerkleLeafPrefix);
        buf.insert(buf.end(), d.begin(), d.end());
        return SHA256::hash(buf);
    };
    auto inter = [](const ChunkHash &l, const ChunkHash &r) {
        std::array<uint8_t, 1 + 64> buf;
        buf[0] = kMerkleIntermediatePrefix;
        std::memcpy(buf.data() + 1, l.data(), 32);
        std::memcpy(buf.data() + 33, r.data(), 32);
        return SHA256::hash(buf);
    };
    ChunkHash l0 = leaf(shards[0]), l1 = leaf(shards[1]), l2 = leaf(shards[2]);
    ChunkHash i0 = inter(l0, l1), i1 = inter(l2, l2);  // 奇数节点补自身
    ChunkHash expected = inter(i0, i1);
    assert(std::memcmp(root.data(), expected.data(), 32) == 0);
}

void test_five_shards() {
    std::vector<std::vector<uint8_t>> shards;
    for (int i = 0; i < 5; ++i) {
        shards.push_back(make_data(50, static_cast<uint8_t>(i + 1)));
    }
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    assert(verify_tensor_merkle_root(spans, root));
}

void test_seven_shards() {
    std::vector<std::vector<uint8_t>> shards;
    for (int i = 0; i < 7; ++i) {
        shards.push_back(make_data(75, static_cast<uint8_t>(i * 3)));
    }
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    assert(verify_tensor_merkle_root(spans, root));
}

// =============================================================================
// 4. 空 tensor（空 shards 列表）
// =============================================================================

void test_empty_shards_returns_zero() {
    std::vector<std::span<const uint8_t>> empty;
    ChunkHash root = compute_merkle_root_from_shards(empty);
    assert(is_zero_root(root));
}

void test_empty_shards_zero_root_verify() {
    // 空 shards + 全零 root → 向后兼容返回 true
    std::vector<std::span<const uint8_t>> empty;
    ChunkHash zero = zero_root();
    assert(verify_tensor_merkle_root(empty, zero));
}

void test_empty_shards_nonzero_root_fails() {
    // 空 shards + 非零 root → 校验失败
    std::vector<std::span<const uint8_t>> empty;
    ChunkHash nonzero = SHA256::hash(make_data(32));
    assert(!is_zero_root(nonzero));
    assert(!verify_tensor_merkle_root(empty, nonzero));
}

// =============================================================================
// 5. tampered shard_data（篡改数据）
// =============================================================================

void test_tampered_shard_data_fails() {
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(make_data(256, 0x01));
    shards.push_back(make_data(256, 0x02));
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);

    // 篡改 shards[1] 的一个字节
    shards[1][100] ^= 0xFF;
    auto tampered_spans = to_spans(shards);
    assert(!verify_tensor_merkle_root(tampered_spans, root));
}

void test_tampered_first_shard_fails() {
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(make_data(512, 0xAA));
    shards.push_back(make_data(512, 0xBB));
    shards.push_back(make_data(512, 0xCC));
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);

    // 篡改第一个 shard
    shards[0][0] ^= 0x01;
    auto tampered = to_spans(shards);
    assert(!verify_tensor_merkle_root(tampered, root));
}

void test_tampered_last_shard_fails() {
    std::vector<std::vector<uint8_t>> shards;
    for (int i = 0; i < 6; ++i) {
        shards.push_back(make_data(128, static_cast<uint8_t>(i)));
    }
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);

    // 篡改最后一个 shard 的末尾字节
    shards.back().back() ^= 0xFF;
    auto tampered = to_spans(shards);
    assert(!verify_tensor_merkle_root(tampered, root));
}

// =============================================================================
// 6. tampered merkle_root（篡改 root）
// =============================================================================

void test_tampered_root_fails() {
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(make_data(256, 0x01));
    shards.push_back(make_data(256, 0x02));
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);

    // 篡改 root 的一个字节
    ChunkHash tampered_root = root;
    tampered_root[0] ^= 0x01;
    assert(!verify_tensor_merkle_root(spans, tampered_root));
}

void test_tampered_root_last_byte_fails() {
    std::vector<std::vector<uint8_t>> shards;
    for (int i = 0; i < 4; ++i) {
        shards.push_back(make_data(64, static_cast<uint8_t>(i)));
    }
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);

    ChunkHash tampered = root;
    tampered[31] ^= 0x80;
    assert(!verify_tensor_merkle_root(spans, tampered));
}

// =============================================================================
// 7. shard 顺序一致性
// =============================================================================

void test_shard_order_matters() {
    // 相同 shard 不同顺序 → 不同 root
    auto s0 = make_data(128, 0x01);
    auto s1 = make_data(128, 0x02);
    auto s2 = make_data(128, 0x03);

    std::vector<std::vector<uint8_t>> order_012 = {s0, s1, s2};
    std::vector<std::vector<uint8_t>> order_120 = {s1, s2, s0};
    std::vector<std::vector<uint8_t>> order_201 = {s2, s0, s1};

    auto root_012 = compute_merkle_root_from_shards(to_spans(order_012));
    auto root_120 = compute_merkle_root_from_shards(to_spans(order_120));
    auto root_201 = compute_merkle_root_from_shards(to_spans(order_201));

    // 不同顺序通常产生不同 root（除非哈希碰撞，概率极低）
    assert(std::memcmp(root_012.data(), root_120.data(), 32) != 0);
    assert(std::memcmp(root_012.data(), root_201.data(), 32) != 0);
}

void test_same_shards_same_root() {
    // 相同输入 → 相同 root（确定性）
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(make_data(256, 0x42));
    shards.push_back(make_data(256, 0x43));
    auto spans = to_spans(shards);

    ChunkHash root1 = compute_merkle_root_from_shards(spans);
    ChunkHash root2 = compute_merkle_root_from_shards(spans);
    assert(std::memcmp(root1.data(), root2.data(), 32) == 0);
}

// =============================================================================
// 8. 与 chunk_hash.compute_merkle_root 互斥性验证
// =============================================================================

void test_different_from_chunk_hash_merkle() {
    // 同样的数据，chunk_hash.compute_merkle_root 和 merkle_tree.compute_merkle_root_from_shards
    // 产生不同的 root（因为叶子里构造不同：双重哈希 vs 单次哈希）
    auto shard = make_data(1024, 0x55);

    // v3.7.0 chunk_hash 方式：先算 chunk_hash，再算 merkle root（叶子 = sha256(0x00||sha256(chunk))）
    ChunkHashList chunk_hashes;
    chunk_hashes.push_back(SHA256::hash(shard));
    ChunkHash chunk_merkle_root = compute_merkle_root(chunk_hashes);

    // v3.8.4 merkle_tree 方式：直接对 shard_data 算 merkle root（叶子 = sha256(0x00||shard_data)）
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(std::move(shard));
    auto spans = to_spans(shards);
    ChunkHash shard_merkle_root = compute_merkle_root_from_shards(spans);

    // 两者必须不同（防止误用）
    assert(std::memcmp(chunk_merkle_root.data(), shard_merkle_root.data(), 32) != 0);
}

// =============================================================================
// 9. zero_root / is_zero_root
// =============================================================================

void test_zero_root_is_zero() {
    ChunkHash z = zero_root();
    assert(is_zero_root(z));
    for (std::size_t i = 0; i < 32; ++i) {
        assert(z[i] == 0);
    }
}

void test_nonzero_root_not_zero() {
    ChunkHash nz = SHA256::hash(make_data(32));
    assert(!is_zero_root(nz));
}

void test_is_zero_root_empty_array() {
    ChunkHash empty{};
    assert(is_zero_root(empty));
}

// =============================================================================
// 10. 大 tensor（模拟大分片）
// =============================================================================

void test_large_shards() {
    // 模拟 4 个 64KB shard（典型 TensorStream shard 大小）
    std::vector<std::vector<uint8_t>> shards;
    for (int i = 0; i < 4; ++i) {
        shards.push_back(make_data(64 * 1024, static_cast<uint8_t>(i)));
    }
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    assert(verify_tensor_merkle_root(spans, root));
}

void test_many_shards() {
    // 模拟 32 个 shard（大 tensor 分片场景）
    std::vector<std::vector<uint8_t>> shards;
    for (int i = 0; i < 32; ++i) {
        shards.push_back(make_data(1024, static_cast<uint8_t>(i)));
    }
    auto spans = to_spans(shards);
    ChunkHash root = compute_merkle_root_from_shards(spans);
    assert(verify_tensor_merkle_root(spans, root));
}

// =============================================================================
// 11. vector<vector<uint8_t>> 便捷重载
// =============================================================================

void test_vector_vector_overload() {
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(make_data(128, 0x01));
    shards.push_back(make_data(128, 0x02));
    shards.push_back(make_data(128, 0x03));

    ChunkHash root = compute_merkle_root_from_shards(to_spans(shards));

    // 便捷重载应与 span 版本结果一致
    assert(verify_tensor_merkle_root(shards, root));
}

void test_vector_vector_tampered() {
    std::vector<std::vector<uint8_t>> shards;
    shards.push_back(make_data(256, 0xAA));
    shards.push_back(make_data(256, 0xBB));

    ChunkHash root = compute_merkle_root_from_shards(to_spans(shards));

    // 篡改
    shards[0][50] ^= 0xFF;
    assert(!verify_tensor_merkle_root(shards, root));
}

// =============================================================================
// 12. 确定性验证
// =============================================================================

void test_deterministic_different_seeds() {
    // 不同 seed 产生不同 root
    std::vector<std::vector<uint8_t>> shards_a;
    shards_a.push_back(make_data(64, 0x01));
    std::vector<std::vector<uint8_t>> shards_b;
    shards_b.push_back(make_data(64, 0x02));

    auto root_a = compute_merkle_root_from_shards(to_spans(shards_a));
    auto root_b = compute_merkle_root_from_shards(to_spans(shards_b));
    assert(std::memcmp(root_a.data(), root_b.data(), 32) != 0);
}

void test_different_sizes_same_seed() {
    // 不同大小但相同 seed 的 shard 产生不同 root
    std::vector<std::vector<uint8_t>> shards_small;
    shards_small.push_back(make_data(32, 0x42));
    std::vector<std::vector<uint8_t>> shards_large;
    shards_large.push_back(make_data(1024, 0x42));

    auto root_small = compute_merkle_root_from_shards(to_spans(shards_small));
    auto root_large = compute_merkle_root_from_shards(to_spans(shards_large));
    assert(std::memcmp(root_small.data(), root_large.data(), 32) != 0);
}

// =============================================================================
// main
// =============================================================================

int main() {
    std::cout << "=== test_merkle_tree (v3.8.4 TensorStream Merkle Root) ===\n";

    std::cout << "[1] 单 shard tensor...\n";
    RUN_TEST(test_single_shard_root);
    RUN_TEST(test_single_shard_verify);
    RUN_TEST(test_single_empty_shard);

    std::cout << "[2] 偶数 shard...\n";
    RUN_TEST(test_two_shards);
    RUN_TEST(test_four_shards);
    RUN_TEST(test_eight_shards);

    std::cout << "[3] 奇数 shard...\n";
    RUN_TEST(test_three_shards);
    RUN_TEST(test_five_shards);
    RUN_TEST(test_seven_shards);

    std::cout << "[4] 空 tensor...\n";
    RUN_TEST(test_empty_shards_returns_zero);
    RUN_TEST(test_empty_shards_zero_root_verify);
    RUN_TEST(test_empty_shards_nonzero_root_fails);

    std::cout << "[5] tampered shard_data...\n";
    RUN_TEST(test_tampered_shard_data_fails);
    RUN_TEST(test_tampered_first_shard_fails);
    RUN_TEST(test_tampered_last_shard_fails);

    std::cout << "[6] tampered merkle_root...\n";
    RUN_TEST(test_tampered_root_fails);
    RUN_TEST(test_tampered_root_last_byte_fails);

    std::cout << "[7] shard 顺序一致性...\n";
    RUN_TEST(test_shard_order_matters);
    RUN_TEST(test_same_shards_same_root);

    std::cout << "[8] 与 chunk_hash 互斥性...\n";
    RUN_TEST(test_different_from_chunk_hash_merkle);

    std::cout << "[9] zero_root / is_zero_root...\n";
    RUN_TEST(test_zero_root_is_zero);
    RUN_TEST(test_nonzero_root_not_zero);
    RUN_TEST(test_is_zero_root_empty_array);

    std::cout << "[10] 大 tensor...\n";
    RUN_TEST(test_large_shards);
    RUN_TEST(test_many_shards);

    std::cout << "[11] vector<vector> 便捷重载...\n";
    RUN_TEST(test_vector_vector_overload);
    RUN_TEST(test_vector_vector_tampered);

    std::cout << "[12] 确定性验证...\n";
    RUN_TEST(test_deterministic_different_seeds);
    RUN_TEST(test_different_sizes_same_seed);

    std::cout << "\n=== 总结: " << test_passed << "/" << test_count
              << " 通过 ===\n";
    return test_passed == test_count ? 0 : 1;
}
