// =============================================================================
// test_chunk_hash.cpp — v3.7.0 可靠性强化：sha256 chunk 校验单元测试
//
// 覆盖：ChunkHasher compute/verify/verify_file + Merkle Root + 序列化辅助
// =============================================================================

#include "linoh/crypto/chunk_hash.hpp"

#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
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

/// 写临时文件
void write_temp_file(const std::string &path, std::span<const uint8_t> data) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    assert(ofs.is_open());
    if (!data.empty()) {
        ofs.write(reinterpret_cast<const char *>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    ofs.close();
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
// ChunkHasher 构造与 chunk_size
// =============================================================================

void test_default_chunk_size() {
    ChunkHasher h;
    assert(h.chunk_size() == ChunkHasher::kDefaultChunkSize);
    assert(h.chunk_size() == 16 * 1024);
}

void test_chunk_size_clamp_min() {
    ChunkHasher h(100);  // 小于 kMinChunkSize
    assert(h.chunk_size() == ChunkHasher::kMinChunkSize);
    assert(h.chunk_size() == 1024);
}

void test_chunk_size_clamp_max() {
    ChunkHasher h(10 * 1024 * 1024);  // 大于 kMaxChunkSize
    assert(h.chunk_size() == ChunkHasher::kMaxChunkSize);
    assert(h.chunk_size() == 1024 * 1024);
}

void test_chunk_size_exact() {
    ChunkHasher h(4096);
    assert(h.chunk_size() == 4096);
}

// =============================================================================
// compute
// =============================================================================

void test_compute_empty() {
    ChunkHasher h(4096);
    ChunkHashList hashes = h.compute({});
    assert(hashes.size() == 1);  // 空数据返回 1 个 chunk
    ChunkHash expected = SHA256::hash({});
    assert(std::memcmp(hashes[0].data(), expected.data(), 32) == 0);
}

void test_compute_exact_multiple() {
    ChunkHasher h(1024);
    auto data = make_data(4096, 1);  // 恰好 4 个 chunk
    ChunkHashList hashes = h.compute(data);
    assert(hashes.size() == 4);
    // 校验每个 chunk 的哈希
    for (std::size_t i = 0; i < 4; ++i) {
        std::span<const uint8_t> chunk(data.data() + i * 1024, 1024);
        ChunkHash expected = SHA256::hash(chunk);
        assert(std::memcmp(hashes[i].data(), expected.data(), 32) == 0);
    }
}

void test_compute_partial_last_chunk() {
    ChunkHasher h(1024);
    auto data = make_data(2500, 2);  // 2 个完整 chunk + 1 个 452 字节 chunk
    ChunkHashList hashes = h.compute(data);
    assert(hashes.size() == 3);
    // 第 3 个 chunk 是 452 字节（2500 - 2*1024）
    std::span<const uint8_t> chunk3(data.data() + 2048, 452);
    ChunkHash expected = SHA256::hash(chunk3);
    assert(std::memcmp(hashes[2].data(), expected.data(), 32) == 0);
}

void test_compute_single_byte() {
    ChunkHasher h(1024);
    std::vector<uint8_t> data = {0xAB};
    ChunkHashList hashes = h.compute(data);
    assert(hashes.size() == 1);
    ChunkHash expected = SHA256::hash(data);
    assert(std::memcmp(hashes[0].data(), expected.data(), 32) == 0);
}

// =============================================================================
// verify
// =============================================================================

void test_verify_match() {
    ChunkHasher h(1024);
    auto data = make_data(4096, 3);
    ChunkHashList hashes = h.compute(data);
    assert(h.verify(data, hashes));
}

void test_verify_data_tampered() {
    ChunkHasher h(1024);
    auto data = make_data(4096, 4);
    ChunkHashList hashes = h.compute(data);
    // 篡改第 2 个 chunk 的第 1 字节
    data[1024] ^= 0xFF;
    assert(!h.verify(data, hashes));
}

void test_verify_hash_tampered() {
    ChunkHasher h(1024);
    auto data = make_data(4096, 5);
    ChunkHashList hashes = h.compute(data);
    // 篡改第 1 个 hash
    hashes[0][0] ^= 0xFF;
    assert(!h.verify(data, hashes));
}

void test_verify_count_mismatch() {
    ChunkHasher h(1024);
    auto data = make_data(4096, 6);
    ChunkHashList hashes = h.compute(data);
    hashes.pop_back();  // 少一个 hash
    assert(!h.verify(data, hashes));
}

void test_verify_empty_data_match() {
    ChunkHasher h(1024);
    ChunkHashList hashes = h.compute({});
    assert(h.verify({}, hashes));
}

void test_verify_empty_data_mismatch() {
    ChunkHasher h(1024);
    ChunkHashList hashes;
    // 空数据但 hashes 也空 → 不匹配（要求至少 1 个）
    assert(!h.verify({}, hashes));
}

// =============================================================================
// compute_from_file + verify_file
// =============================================================================

void test_compute_from_file() {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "linoh_test_chunk_hash_file.bin";
    auto data = make_data(5000, 7);  // 5 个 chunk（4096 + 904）
    write_temp_file(tmp.string(), data);

    ChunkHasher h(1024);
    std::size_t total = 0;
    ChunkHashList hashes = h.compute_from_file(tmp.string(), &total);
    assert(total == 5000);
    assert(hashes.size() == 5);

    // 与内存计算结果一致
    ChunkHashList mem_hashes = h.compute(data);
    assert(hashes.size() == mem_hashes.size());
    for (std::size_t i = 0; i < hashes.size(); ++i) {
        assert(std::memcmp(hashes[i].data(), mem_hashes[i].data(), 32) == 0);
    }

    fs::remove(tmp);
}

void test_compute_from_file_empty() {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "linoh_test_chunk_hash_empty.bin";
    write_temp_file(tmp.string(), {});

    ChunkHasher h(1024);
    std::size_t total = 99;
    ChunkHashList hashes = h.compute_from_file(tmp.string(), &total);
    assert(total == 0);
    assert(hashes.size() == 1);

    fs::remove(tmp);
}

void test_compute_from_file_not_exist() {
    ChunkHasher h(1024);
    ChunkHashList hashes = h.compute_from_file("nonexistent_file_xyz.bin");
    assert(hashes.empty());
}

void test_verify_file_match() {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "linoh_test_chunk_verify.bin";
    auto data = make_data(3000, 8);
    write_temp_file(tmp.string(), data);

    ChunkHasher h(1024);
    ChunkHashList hashes = h.compute(data);
    assert(h.verify_file(tmp.string(), hashes, 3000));

    fs::remove(tmp);
}

void test_verify_file_size_mismatch() {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "linoh_test_chunk_verify_size.bin";
    auto data = make_data(3000, 9);
    write_temp_file(tmp.string(), data);

    ChunkHasher h(1024);
    ChunkHashList hashes = h.compute(data);
    assert(!h.verify_file(tmp.string(), hashes, 9999));  // 大小不匹配

    fs::remove(tmp);
}

void test_verify_file_data_tampered() {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "linoh_test_chunk_verify_tamper.bin";
    auto data = make_data(3000, 10);
    write_temp_file(tmp.string(), data);

    ChunkHasher h(1024);
    ChunkHashList hashes = h.compute(data);

    // 篡改文件
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::in | std::ios::out);
        assert(ofs.is_open());
        ofs.seekp(1500);
        char c = 0xFF;
        ofs.write(&c, 1);
    }

    assert(!h.verify_file(tmp.string(), hashes, 3000));

    fs::remove(tmp);
}

// =============================================================================
// Merkle Root
// =============================================================================

void test_merkle_root_empty() {
    ChunkHashList empty;
    ChunkHash root = compute_merkle_root(empty);
    // 空列表返回全零
    for (std::size_t i = 0; i < 32; ++i) {
        assert(root[i] == 0);
    }
}

void test_merkle_root_single_chunk() {
    ChunkHasher h(1024);
    auto data = make_data(500, 11);
    ChunkHashList hashes = h.compute(data);
    assert(hashes.size() == 1);
    ChunkHash root = compute_merkle_root(hashes);
    // 单 chunk：root = sha256(0x00 || chunk_hash)
    std::array<uint8_t, 33> buf;
    buf[0] = kMerkleLeafPrefix;
    std::memcpy(buf.data() + 1, hashes[0].data(), 32);
    ChunkHash expected = SHA256::hash(buf);
    assert(std::memcmp(root.data(), expected.data(), 32) == 0);
}

void test_merkle_root_two_chunks() {
    ChunkHasher h(1024);
    auto data = make_data(2048, 12);  // 2 chunks
    ChunkHashList hashes = h.compute(data);
    assert(hashes.size() == 2);
    ChunkHash root = compute_merkle_root(hashes);
    // root = sha256(0x01 || leaf0 || leaf1)
    std::array<uint8_t, 33> buf0;
    buf0[0] = kMerkleLeafPrefix;
    std::memcpy(buf0.data() + 1, hashes[0].data(), 32);
    ChunkHash leaf0 = SHA256::hash(buf0);

    std::array<uint8_t, 33> buf1;
    buf1[0] = kMerkleLeafPrefix;
    std::memcpy(buf1.data() + 1, hashes[1].data(), 32);
    ChunkHash leaf1 = SHA256::hash(buf1);

    std::array<uint8_t, 65> buf_mid;
    buf_mid[0] = kMerkleIntermediatePrefix;
    std::memcpy(buf_mid.data() + 1, leaf0.data(), 32);
    std::memcpy(buf_mid.data() + 33, leaf1.data(), 32);
    ChunkHash expected = SHA256::hash(buf_mid);
    assert(std::memcmp(root.data(), expected.data(), 32) == 0);
}

void test_merkle_root_odd_chunks() {
    ChunkHasher h(1024);
    auto data = make_data(3000, 13);  // 3 chunks
    ChunkHashList hashes = h.compute(data);
    assert(hashes.size() == 3);
    ChunkHash root = compute_merkle_root(hashes);
    // 不为空即可（奇数节点补自身）
    bool all_zero = true;
    for (std::size_t i = 0; i < 32; ++i) {
        if (root[i] != 0) { all_zero = false; break; }
    }
    assert(!all_zero);
}

void test_merkle_root_deterministic() {
    ChunkHasher h(1024);
    auto data = make_data(5000, 14);
    ChunkHashList hashes = h.compute(data);
    ChunkHash root1 = compute_merkle_root(hashes);
    ChunkHash root2 = compute_merkle_root(hashes);
    assert(std::memcmp(root1.data(), root2.data(), 32) == 0);
}

void test_verify_merkle_root_match() {
    ChunkHasher h(1024);
    auto data = make_data(4000, 15);
    ChunkHashList hashes = h.compute(data);
    ChunkHash root = compute_merkle_root(hashes);
    assert(verify_merkle_root(data, 1024, root));
}

void test_verify_merkle_root_tampered() {
    ChunkHasher h(1024);
    auto data = make_data(4000, 16);
    ChunkHashList hashes = h.compute(data);
    ChunkHash root = compute_merkle_root(hashes);
    // 篡改数据
    data[100] ^= 0xFF;
    assert(!verify_merkle_root(data, 1024, root));
}

void test_verify_merkle_root_wrong_chunk_size() {
    ChunkHasher h(1024);
    auto data = make_data(4000, 17);
    ChunkHashList hashes = h.compute(data);
    ChunkHash root = compute_merkle_root(hashes);
    // 用错误的 chunk_size 验证
    assert(!verify_merkle_root(data, 2048, root));
}

// =============================================================================
// 序列化辅助
// =============================================================================

void test_serialize_deserialize() {
    ChunkHasher h(1024);
    auto data = make_data(3000, 18);
    ChunkHashList hashes = h.compute(data);
    auto bytes = serialize_chunk_hash_list(hashes);
    assert(bytes.size() == hashes.size() * 32);
    ChunkHashList restored = deserialize_chunk_hash_list(bytes);
    assert(restored.size() == hashes.size());
    for (std::size_t i = 0; i < hashes.size(); ++i) {
        assert(std::memcmp(restored[i].data(), hashes[i].data(), 32) == 0);
    }
}

void test_deserialize_invalid_length() {
    std::vector<uint8_t> bad(33);  // 非 32 倍数
    ChunkHashList restored = deserialize_chunk_hash_list(bad);
    assert(restored.empty());
}

void test_to_hex_from_hex() {
    ChunkHash h;
    for (std::size_t i = 0; i < 32; ++i) h[i] = static_cast<uint8_t>(i);
    std::string hex = to_hex(h);
    assert(hex.size() == 64);
    ChunkHash restored;
    assert(from_hex(hex, restored));
    assert(std::memcmp(h.data(), restored.data(), 32) == 0);
}

void test_from_hex_invalid() {
    ChunkHash h;
    assert(!from_hex("short", h));         // 长度不足
    assert(!from_hex(std::string(64, 'x'), h));  // 非 hex 字符
}

void test_to_hex_known_value() {
    // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    ChunkHash empty_hash = SHA256::hash({});
    std::string hex = to_hex(empty_hash);
    assert(hex.size() == 64);
    assert(hex.substr(0, 8) == "e3b0c442");
}

// =============================================================================
// main
// =============================================================================

int main() {
    std::cout << "=== test_chunk_hash v3.7.0 ===\n";

    std::cout << "-- ChunkHasher 构造与 chunk_size\n";
    RUN_TEST(test_default_chunk_size);
    RUN_TEST(test_chunk_size_clamp_min);
    RUN_TEST(test_chunk_size_clamp_max);
    RUN_TEST(test_chunk_size_exact);

    std::cout << "-- compute\n";
    RUN_TEST(test_compute_empty);
    RUN_TEST(test_compute_exact_multiple);
    RUN_TEST(test_compute_partial_last_chunk);
    RUN_TEST(test_compute_single_byte);

    std::cout << "-- verify\n";
    RUN_TEST(test_verify_match);
    RUN_TEST(test_verify_data_tampered);
    RUN_TEST(test_verify_hash_tampered);
    RUN_TEST(test_verify_count_mismatch);
    RUN_TEST(test_verify_empty_data_match);
    RUN_TEST(test_verify_empty_data_mismatch);

    std::cout << "-- compute_from_file + verify_file\n";
    RUN_TEST(test_compute_from_file);
    RUN_TEST(test_compute_from_file_empty);
    RUN_TEST(test_compute_from_file_not_exist);
    RUN_TEST(test_verify_file_match);
    RUN_TEST(test_verify_file_size_mismatch);
    RUN_TEST(test_verify_file_data_tampered);

    std::cout << "-- Merkle Root\n";
    RUN_TEST(test_merkle_root_empty);
    RUN_TEST(test_merkle_root_single_chunk);
    RUN_TEST(test_merkle_root_two_chunks);
    RUN_TEST(test_merkle_root_odd_chunks);
    RUN_TEST(test_merkle_root_deterministic);
    RUN_TEST(test_verify_merkle_root_match);
    RUN_TEST(test_verify_merkle_root_tampered);
    RUN_TEST(test_verify_merkle_root_wrong_chunk_size);

    std::cout << "-- 序列化辅助\n";
    RUN_TEST(test_serialize_deserialize);
    RUN_TEST(test_deserialize_invalid_length);
    RUN_TEST(test_to_hex_from_hex);
    RUN_TEST(test_from_hex_invalid);
    RUN_TEST(test_to_hex_known_value);

    std::cout << "\n[OK] test_chunk_hash passed: " << test_passed << "/"
              << test_count << " tests\n";
    return 0;
}
