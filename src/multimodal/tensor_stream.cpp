// tensor_stream.cpp — 大 tensor 分片 + 重组实现（P5-A-3）

#include "linoh/multimodal/tensor_stream.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include "linoh/crypto/merkle_tree.hpp"
#include "linoh/util/logging.hpp"

namespace linoh::multimodal {

// ============================================================================
// TensorMeta 序列化/反序列化（48 字节固定头部）
// ============================================================================

std::array<std::uint8_t, 48> TensorMeta::serialize() const {
    std::array<std::uint8_t, 48> buf{};
    auto put_u64 = [&](std::size_t off, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF);
    };
    auto put_u32 = [&](std::size_t off, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF);
    };
    put_u64(0, tensor_id);
    put_u32(8, total_shards);
    put_u32(12, shard_idx);
    buf[16] = static_cast<std::uint8_t>(dtype);
    // [17..18] reserved
    put_u32(19, shape[0]);
    put_u32(23, shape[1]);
    put_u32(27, shape[2]);
    put_u32(31, shape[3]);
    put_u64(35, total_bytes);
    put_u32(43, shard_bytes);
    buf[47] = is_last ? 1 : 0;
    return buf;
}

bool TensorMeta::parse(std::span<const std::uint8_t> data, TensorMeta &out) {
    if (data.size() < 48) return false;
    auto get_u64 = [&](std::size_t off) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(data[off + i]) << (i * 8);
        return v;
    };
    auto get_u32 = [&](std::size_t off) -> std::uint32_t {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<std::uint32_t>(data[off + i]) << (i * 8);
        return v;
    };
    out.tensor_id     = get_u64(0);
    out.total_shards  = get_u32(8);
    out.shard_idx     = get_u32(12);
    // mp-M8 (v1.7.0.8): 校验 dtype 范围，防止恶意/损坏帧构造非法 TensorDType
    // 导致后续 dtype_name/dtype_size 的 switch 未命中返回 "unknown"/0，
    // 进一步可能触发 padded_bytes 计算为 0 → 缓冲区未分配 → 解引用 UAF。
    // TensorDType 枚举当前 8 个值（F32=0..I8=7），data[16] > 7 视为非法。
    if (data[16] > 7) {
        LINOH_WARN("TensorMeta::parse: invalid dtype=", static_cast<unsigned>(data[16]),
                   " (must be 0..7), rejecting frame");
        return false;
    }
    out.dtype         = static_cast<TensorDType>(data[16]);
    out.shape[0]      = get_u32(19);
    out.shape[1]      = get_u32(23);
    out.shape[2]      = get_u32(27);
    out.shape[3]      = get_u32(31);
    out.total_bytes   = get_u64(35);
    out.shard_bytes   = get_u32(43);
    out.is_last       = (data[47] != 0);
    return true;
}

// ============================================================================
// TensorMeta v3.8.4: merkle_root 内存字段辅助
// ============================================================================

bool TensorMeta::has_merkle_root() const noexcept {
    for (std::size_t i = 0; i < 32; ++i) {
        if (merkle_root[i] != 0) return true;
    }
    return false;
}

// ============================================================================
// TensorShardMessage 序列化/反序列化（48B 头 + data）
// ============================================================================

std::vector<std::uint8_t> TensorShardMessage::serialize() const {
    auto header = meta.serialize();
    std::vector<std::uint8_t> buf;
    buf.reserve(48 + data.size());
    buf.insert(buf.end(), header.begin(), header.end());
    buf.insert(buf.end(), data.begin(), data.end());
    return buf;
}

bool TensorShardMessage::parse(std::span<const std::uint8_t> data, TensorShardMessage &out) {
    if (!TensorMeta::parse(data, out.meta)) return false;
    if (data.size() < 48 + out.meta.shard_bytes) return false;
    out.data.assign(data.begin() + 48, data.begin() + 48 + out.meta.shard_bytes);
    return true;
}

// ============================================================================
// v3.9.6 M17: ShardHashAnnouncePayload 序列化/反序列化
// ============================================================================

std::vector<std::uint8_t> ShardHashAnnouncePayload::serialize() const {
    std::vector<std::uint8_t> buf;
    const std::size_t hash_bytes = chunk_hashes.size() * crypto::SHA256::kDigestSize;
    buf.reserve(kHeaderSize + hash_bytes);

    // 固定头部 20 字节（小端序）
    auto put_u64 = [&](std::size_t off, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF);
    };
    auto put_u32 = [&](std::size_t off, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF);
    };

    buf.resize(kHeaderSize);
    put_u64(0, tensor_id);
    put_u32(8, shard_idx);
    put_u32(12, chunk_size);
    put_u32(16, static_cast<std::uint32_t>(chunk_hashes.size()));

    // 拼接 chunk hash 列表（每个 32 字节）
    for (const auto &hash : chunk_hashes) {
        buf.insert(buf.end(), hash.begin(), hash.end());
    }
    return buf;
}

bool ShardHashAnnouncePayload::parse(std::span<const std::uint8_t> data,
                                      ShardHashAnnouncePayload &out) {
    if (data.size() < kHeaderSize) return false;

    auto get_u64 = [&](std::size_t off) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(data[off + i]) << (i * 8);
        return v;
    };
    auto get_u32 = [&](std::size_t off) -> std::uint32_t {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<std::uint32_t>(data[off + i]) << (i * 8);
        return v;
    };

    out.tensor_id   = get_u64(0);
    out.shard_idx   = get_u32(8);
    out.chunk_size  = get_u32(12);
    std::uint32_t count = get_u32(16);

    // 校验 hash 数据长度
    const std::size_t expected_hash_bytes =
        static_cast<std::size_t>(count) * crypto::SHA256::kDigestSize;
    if (data.size() < kHeaderSize + expected_hash_bytes) return false;

    out.chunk_hashes.resize(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::size_t off = kHeaderSize + static_cast<std::size_t>(i) * crypto::SHA256::kDigestSize;
        std::memcpy(out.chunk_hashes[i].data(), data.data() + off, crypto::SHA256::kDigestSize);
    }
    return true;
}

// ============================================================================
// TensorReassembler
// ============================================================================

// v1.5 P1-3: 判断单个 tensor 是否超时（毫秒级精度）
static inline bool tensor_is_expired(const TensorReassemblyState &state,
                                    std::chrono::steady_clock::time_point now,
                                    std::chrono::seconds timeout_s,
                                    std::chrono::milliseconds timeout_ms_residue) {
    if (!state.first_received) return false;
    auto elapsed = now - state.first_seen_time;
    if (timeout_ms_residue.count() > 0) {
        // 毫秒级精度（测试用）
        return elapsed > timeout_ms_residue;
    }
    return elapsed > timeout_s;
}

void TensorReassembler::on_complete(CompleteCallback cb) {
    std::lock_guard<std::mutex> lk(callback_mu_);
    callback_ = std::move(cb);
    // mp-P9: 同步原子标志，供 on_shard 桶锁内无锁判断
    has_callback_.store(callback_ ? true : false, std::memory_order_release);
}

bool TensorReassembler::on_shard(const TensorShardMessage &shard) {
    const std::uint64_t tid = shard.meta.tensor_id;
    const std::size_t bidx = bucket_index(tid);

    // ===== 第 1 步：recent_evicted_ 查重（独立锁，不持桶锁）=====
    // mp-L8 防迟到 shard 重建：若 tensor 已被驱逐，直接丢弃
    {
        std::lock_guard<std::mutex> lk(evicted_mu_);
        for (const auto &entry : recent_evicted_) {
            if (entry.first == tid) {
                LINOH_DEBUG("TensorReassembler: dropping late shard for evicted tensor_id=",
                            static_cast<unsigned long long>(tid),
                            " shard_idx=", shard.meta.shard_idx);
                return false;
            }
        }
    }

    // ===== 第 2 步：读取配置（独立锁，低频）=====
    std::chrono::seconds timeout_s;
    std::chrono::milliseconds ms_res;
    {
        std::lock_guard<std::mutex> lk(config_mu_);
        timeout_s = auto_cleanup_timeout_;
        ms_res = ms_residue_;
    }

    // ===== 第 3 步：桶内节流清理 + 分片登记（持桶锁）=====
    //   accepted 语义与原实现一致：重复/越界=false，接受=true
    //   所有早退路径都通过统一退出块处理 expired_in_bucket，避免跳过驱逐记录
    bool accepted = false;
    bool completed = false;
    TensorReassemblyState st;
    std::vector<std::uint8_t> full_data;
    std::vector<std::uint64_t> expired_in_bucket;  // 桶内过期 tid（锁外追加到 recent_evicted_）

    {
        Bucket &bucket = buckets_[bidx];
        std::lock_guard<std::mutex> lk(bucket.mu);

        // mp-P3 桶级节流清理：距上次清理 > kCleanupIntervalMs 才扫描本桶
        //   首次调用 last_cleanup_time 为 epoch，now - epoch 必定 > 100ms，首次一定执行
        {
            auto now = std::chrono::steady_clock::now();
            if (now - bucket.last_cleanup_time >= kCleanupIntervalMs) {
                bucket.last_cleanup_time = now;
                cleanup_bucket_locked_(bucket, now, timeout_s, ms_res, expired_in_bucket);
            }
        }

        auto &state = bucket.buffers[tid];
        if (!state.first_received) {
            state.first_meta = shard.meta;
            state.first_received = true;
            state.first_seen_time = std::chrono::steady_clock::now();  // v1.5 P1-3: 记录首片接收时间
        }
        // 重复分片检查
        if (state.shards.find(shard.meta.shard_idx) != state.shards.end()) {
            // 已收到过该分片，忽略（accepted 保持 false）
        } else if (shard.meta.shard_idx >= shard.meta.total_shards) {
            // 校验 shard_idx 不越界
            LINOH_WARN("TensorReassembler: shard_idx %u >= total_shards %u (tensor_id=%llu)",
                       shard.meta.shard_idx, shard.meta.total_shards,
                       static_cast<unsigned long long>(tid));
            // accepted 保持 false
        } else {
            state.shards[shard.meta.shard_idx] = shard.data;
            state.received_count++;
            accepted = true;  // 被接受

            // 检查是否所有分片到齐
            if (state.shards.size() == state.first_meta.total_shards) {
                // 所有分片到齐，拷贝状态（仍在桶锁内）
                st = state;
                full_data.reserve(st.first_meta.total_bytes);
                for (auto &kv : st.shards) {
                    full_data.insert(full_data.end(), kv.second.begin(), kv.second.end());
                }
                completed = true;
                // mp-P9: 仅在有回调时立即从桶内移除，避免回调期间迟到 shard 重新登记
                //   无回调时保留状态，便于上层通过 state() 查询完整数据（保持重构前行为）
                //   has_callback_ 为 atomic，桶锁内无锁读取安全
                if (has_callback_.load(std::memory_order_acquire)) {
                    bucket.buffers.erase(tid);
                }
            }
        }
    }  // 桶锁释放

    // ===== 第 4 步：将桶内过期 tid 追加到全局 recent_evicted_（锁外）=====
    //    严格顺序：先释放桶锁，再加 evicted_mu_，避免锁顺序反转死锁
    if (!expired_in_bucket.empty()) {
        std::lock_guard<std::mutex> lk(evicted_mu_);
        auto now = std::chrono::steady_clock::now();
        for (auto expired_tid : expired_in_bucket) {
            recent_evicted_.emplace_back(expired_tid, now);
        }
        // LRU 淘汰最旧条目
        while (recent_evicted_.size() > kMaxRecentEvicted) {
            auto oldest = std::min_element(recent_evicted_.begin(), recent_evicted_.end(),
                [](const auto &a, const auto &b) { return a.second < b.second; });
            if (oldest != recent_evicted_.end()) {
                recent_evicted_.erase(oldest);
            } else {
                break;
            }
        }
    }

    // ===== 第 4.5 步：v3.9.6 M17 逐 chunk 校验（锁外，仅对已接受的 shard）=====
    if (accepted) {
        verify_shard_chunks_(tid, shard.meta.shard_idx, shard.data);
    }

    // ===== 第 5 步：锁外触发完成回调 =====
    if (completed) {
        // v3.8.4: Merkle Root 完整性校验（在完成回调前执行）
        bool merkle_ok = true;
        if (should_verify_merkle_(tid, st.first_meta.is_last)) {
            std::array<std::uint8_t, 32> expected_root{};
            if (get_expected_root_(tid, expected_root)) {
                // st.shards 是 map<shard_idx, data>，已按 shard_idx 排序
                std::vector<std::vector<std::uint8_t>> shard_list;
                shard_list.reserve(st.shards.size());
                for (const auto &kv : st.shards) {
                    shard_list.push_back(kv.second);
                }
                if (!crypto::verify_tensor_merkle_root(shard_list, expected_root)) {
                    merkle_ok = false;
                    // 计算实际 root 用于失败回调
                    std::vector<std::span<const std::uint8_t>> spans;
                    spans.reserve(shard_list.size());
                    for (const auto &s : shard_list) {
                        spans.emplace_back(s.data(), s.size());
                    }
                    auto actual_root = crypto::compute_merkle_root_from_shards(spans);
                    LINOH_WARN("TensorReassembler: merkle verification FAILED for tensor_id=",
                               static_cast<unsigned long long>(tid),
                               " (shards=", st.shards.size(), ")");
                    // 触发失败回调
                    MerkleFailureCallback fail_cb;
                    {
                        std::lock_guard<std::mutex> lk(merkle_cb_mu_);
                        fail_cb = merkle_failure_cb_;
                    }
                    if (fail_cb) {
                        try {
                            fail_cb(tid, expected_root, actual_root);
                        } catch (...) {
                            LINOH_ERROR("TensorReassembler: merkle failure callback threw exception");
                        }
                    }
                }
            }
        }

        if (merkle_ok) {
            CompleteCallback cb_copy;
            {
                std::lock_guard<std::mutex> lk(callback_mu_);
                cb_copy = callback_;  // 拷贝以避免回调期间被替换
            }
            if (cb_copy) {
                try {
                    cb_copy(tid, std::move(full_data), st.first_meta);
                } catch (...) {
                    LINOH_ERROR("TensorReassembler: callback threw exception");
                }
            }
        }
        // 注意：已完成 tensor 在第 3 步已从桶内 erase，无需再次 cleanup
    }
    return accepted;
}

float TensorReassembler::progress(std::uint64_t tensor_id) const {
    const std::size_t bidx = bucket_index(tensor_id);
    std::lock_guard<std::mutex> lk(buckets_[bidx].mu);
    auto it = buckets_[bidx].buffers.find(tensor_id);
    if (it == buckets_[bidx].buffers.end()) return 0.0f;
    if (it->second.first_meta.total_shards == 0) return 0.0f;
    return static_cast<float>(it->second.shards.size()) /
           static_cast<float>(it->second.first_meta.total_shards);
}

std::size_t TensorReassembler::pending_count() const {
    // mp-P9: 遍历所有桶求和。每桶独立加锁，不持锁跨越多个桶（避免死锁）
    std::size_t total = 0;
    for (auto &bucket : buckets_) {
        std::lock_guard<std::mutex> lk(bucket.mu);
        total += bucket.buffers.size();
    }
    return total;
}

std::optional<TensorReassemblyState> TensorReassembler::state(std::uint64_t tensor_id) const {
    const std::size_t bidx = bucket_index(tensor_id);
    std::lock_guard<std::mutex> lk(buckets_[bidx].mu);
    auto it = buckets_[bidx].buffers.find(tensor_id);
    if (it == buckets_[bidx].buffers.end()) return std::nullopt;
    return it->second;
}

void TensorReassembler::cleanup(std::uint64_t tensor_id) {
    const std::size_t bidx = bucket_index(tensor_id);
    std::lock_guard<std::mutex> lk(buckets_[bidx].mu);
    buckets_[bidx].buffers.erase(tensor_id);
}

void TensorReassembler::clear() {
    // mp-P9: 遍历所有桶清空 + 清空全局驱逐记录
    for (auto &bucket : buckets_) {
        std::lock_guard<std::mutex> lk(bucket.mu);
        bucket.buffers.clear();
        bucket.last_cleanup_time = {};  // mp-P3: 重置节流计时器
    }
    std::lock_guard<std::mutex> lk(evicted_mu_);
    recent_evicted_.clear();
}

// v1.5 P1-3: 手动触发一次超时清理（返回被清理的 tensor 数）
std::size_t TensorReassembler::run_auto_cleanup() {
    // mp-P9: 遍历所有桶执行清理，汇总 expired 后锁外追加到 recent_evicted_
    std::chrono::seconds timeout_s;
    std::chrono::milliseconds ms_res;
    {
        std::lock_guard<std::mutex> lk(config_mu_);
        timeout_s = auto_cleanup_timeout_;
        ms_res = ms_residue_;
    }

    std::size_t total_expired = 0;
    std::vector<std::uint64_t> all_expired;

    for (auto &bucket : buckets_) {
        std::vector<std::uint64_t> expired_in_bucket;
        std::lock_guard<std::mutex> lk(bucket.mu);
        auto now = std::chrono::steady_clock::now();
        // mp-P3: 手动清理也更新节流计时器，避免下次 on_shard 立即重复扫描
        bucket.last_cleanup_time = now;
        cleanup_bucket_locked_(bucket, now, timeout_s, ms_res, expired_in_bucket);
        total_expired += expired_in_bucket.size();
        all_expired.insert(all_expired.end(),
                           expired_in_bucket.begin(), expired_in_bucket.end());
    }

    // 锁外追加到全局 recent_evicted_
    if (!all_expired.empty()) {
        std::lock_guard<std::mutex> lk(evicted_mu_);
        auto now = std::chrono::steady_clock::now();
        for (auto expired_tid : all_expired) {
            recent_evicted_.emplace_back(expired_tid, now);
        }
        while (recent_evicted_.size() > kMaxRecentEvicted) {
            auto oldest = std::min_element(recent_evicted_.begin(), recent_evicted_.end(),
                [](const auto &a, const auto &b) { return a.second < b.second; });
            if (oldest != recent_evicted_.end()) {
                recent_evicted_.erase(oldest);
            } else {
                break;
            }
        }
    }
    return total_expired;
}

// mp-P9: 桶内清理（持桶锁调用）
void TensorReassembler::cleanup_bucket_locked_(
    Bucket &bucket,
    std::chrono::steady_clock::time_point now,
    std::chrono::seconds timeout_s,
    std::chrono::milliseconds ms_res,
    std::vector<std::uint64_t> &expired_out) {
    // 调用方已持 bucket.mu
    expired_out.clear();
    expired_out.reserve(bucket.buffers.size());
    for (auto &kv : bucket.buffers) {
        if (tensor_is_expired(kv.second, now, timeout_s, ms_res)) {
            expired_out.push_back(kv.first);
        }
    }
    for (auto expired_tid : expired_out) {
        LINOH_WARN("TensorReassembler: auto cleanup tensor_id=",
                   static_cast<unsigned long long>(expired_tid), "(timeout)");
        bucket.buffers.erase(expired_tid);
    }
}

// mp-P9: 配置读写方法（加锁）
void TensorReassembler::set_auto_cleanup_timeout(std::chrono::seconds t) {
    std::lock_guard<std::mutex> lk(config_mu_);
    auto_cleanup_timeout_ = t;
}

void TensorReassembler::set_auto_cleanup_timeout_ms(std::chrono::milliseconds t) {
    std::lock_guard<std::mutex> lk(config_mu_);
    auto_cleanup_timeout_ = std::chrono::duration_cast<std::chrono::seconds>(t);
    if (auto_cleanup_timeout_.count() == 0 && t.count() > 0) {
        // 避免小于 1s 被 cast 后归零，单独记录 ms 尾数
        ms_residue_ = t;
    } else {
        ms_residue_ = std::chrono::milliseconds(0);
    }
}

std::chrono::seconds TensorReassembler::auto_cleanup_timeout() const {
    std::lock_guard<std::mutex> lk(config_mu_);
    return auto_cleanup_timeout_;
}

void TensorReassembler::maybe_complete(std::uint64_t tensor_id) {
    // 已在 on_shard 中处理
    (void)tensor_id;
}

// ============================================================================
// v3.8.4: Merkle Root 完整性校验
// ============================================================================

void TensorReassembler::set_expected_merkle_root(
    std::uint64_t tensor_id,
    const std::array<std::uint8_t, 32> &merkle_root) {
    std::lock_guard<std::mutex> lk(merkle_roots_mu_);
    expected_merkle_roots_[tensor_id] = merkle_root;
}

void TensorReassembler::clear_expected_merkle_root(std::uint64_t tensor_id) {
    std::lock_guard<std::mutex> lk(merkle_roots_mu_);
    expected_merkle_roots_.erase(tensor_id);
}

void TensorReassembler::set_verify_merkle(bool enable) noexcept {
    verify_merkle_enabled_.store(enable, std::memory_order_release);
}

bool TensorReassembler::verify_merkle_enabled() const noexcept {
    return verify_merkle_enabled_.load(std::memory_order_acquire);
}

void TensorReassembler::set_mid_hop_verify(bool enable) noexcept {
    mid_hop_verify_enabled_.store(enable, std::memory_order_release);
}

bool TensorReassembler::mid_hop_verify_enabled() const noexcept {
    return mid_hop_verify_enabled_.load(std::memory_order_acquire);
}

void TensorReassembler::on_merkle_failure(MerkleFailureCallback cb) {
    std::lock_guard<std::mutex> lk(merkle_cb_mu_);
    merkle_failure_cb_ = std::move(cb);
}

bool TensorReassembler::should_verify_merkle_(std::uint64_t tensor_id,
                                                bool is_last) const {
    if (!verify_merkle_enabled_.load(std::memory_order_acquire)) return false;
    // 仅末节点校验，或显式启用中间节点校验
    if (!is_last && !mid_hop_verify_enabled_.load(std::memory_order_acquire)) {
        return false;
    }
    // 检查是否有该 tensor 的期望 root
    std::lock_guard<std::mutex> lk(merkle_roots_mu_);
    auto it = expected_merkle_roots_.find(tensor_id);
    if (it == expected_merkle_roots_.end()) return false;
    // 全零 root 表示无需校验（向后兼容）
    for (std::size_t i = 0; i < 32; ++i) {
        if (it->second[i] != 0) return true;
    }
    return false;
}

bool TensorReassembler::get_expected_root_(
    std::uint64_t tensor_id,
    std::array<std::uint8_t, 32> &out) const {
    std::lock_guard<std::mutex> lk(merkle_roots_mu_);
    auto it = expected_merkle_roots_.find(tensor_id);
    if (it == expected_merkle_roots_.end()) return false;
    out = it->second;
    // 全零 root 返回 false（无需校验）
    for (std::size_t i = 0; i < 32; ++i) {
        if (out[i] != 0) return true;
    }
    return false;
}

// ============================================================================
// v3.9.6 M17: 逐 chunk 增量校验
// ============================================================================

void TensorReassembler::set_expected_chunk_hashes(
    std::uint64_t tensor_id,
    std::uint32_t shard_idx,
    std::uint32_t chunk_size,
    crypto::ChunkHashList hashes) {
    std::lock_guard<std::mutex> lk(chunk_hashes_mu_);
    expected_chunk_hashes_[chunk_hash_key_(tensor_id, shard_idx)] =
        {chunk_size, std::move(hashes)};
}

void TensorReassembler::clear_expected_chunk_hashes(std::uint64_t tensor_id,
                                                     std::uint32_t shard_idx) {
    std::lock_guard<std::mutex> lk(chunk_hashes_mu_);
    expected_chunk_hashes_.erase(chunk_hash_key_(tensor_id, shard_idx));
}

void TensorReassembler::clear_tensor_chunk_hashes(std::uint64_t tensor_id) {
    std::lock_guard<std::mutex> lk(chunk_hashes_mu_);
    // 遍历删除所有匹配 tensor_id 高 32 位的条目
    for (auto it = expected_chunk_hashes_.begin(); it != expected_chunk_hashes_.end();) {
        if ((it->first >> 32) == tensor_id) {
            it = expected_chunk_hashes_.erase(it);
        } else {
            ++it;
        }
    }
}

void TensorReassembler::set_verify_chunk_hashes(bool enable) noexcept {
    verify_chunk_hashes_enabled_.store(enable, std::memory_order_release);
}

bool TensorReassembler::verify_chunk_hashes_enabled() const noexcept {
    return verify_chunk_hashes_enabled_.load(std::memory_order_acquire);
}

void TensorReassembler::on_chunk_verify_failure(ChunkVerifyFailureCallback cb) {
    std::lock_guard<std::mutex> lk(chunk_cb_mu_);
    chunk_failure_cb_ = std::move(cb);
}

bool TensorReassembler::verify_shard_chunks_(
    std::uint64_t tensor_id,
    std::uint32_t shard_idx,
    std::span<const std::uint8_t> shard_data) {
    // 快速路径：未启用 chunk 校验
    if (!verify_chunk_hashes_enabled_.load(std::memory_order_acquire)) {
        return true;
    }

    // 读取期望的 chunk hash 列表（拷贝，锁外校验）
    std::uint32_t chunk_size = 0;
    crypto::ChunkHashList expected_hashes;
    {
        std::lock_guard<std::mutex> lk(chunk_hashes_mu_);
        auto it = expected_chunk_hashes_.find(chunk_hash_key_(tensor_id, shard_idx));
        if (it == expected_chunk_hashes_.end()) {
            return true;  // 无期望 hash，无需校验
        }
        chunk_size = it->second.first;
        expected_hashes = it->second.second;  // 拷贝（ChunkHashList = vector<array<32>>）
    }

    // 空 hash 列表表示无需校验
    if (expected_hashes.empty()) {
        return true;
    }

    // chunk_size 为 0 时用默认值
    if (chunk_size == 0) {
        chunk_size = static_cast<std::uint32_t>(crypto::ChunkHasher::kDefaultChunkSize);
    }

    // 用 ChunkHasher 计算实际 chunk hash 并逐 chunk 比对
    crypto::ChunkHasher hasher(chunk_size);
    auto actual_hashes = hasher.compute(shard_data);

    bool all_ok = true;

    // 长度不匹配也算校验失败
    if (actual_hashes.size() != expected_hashes.size()) {
        LINOH_WARN("TensorReassembler: chunk count mismatch for tensor_id=",
                   static_cast<unsigned long long>(tensor_id),
                   " shard_idx=", shard_idx,
                   " expected=", expected_hashes.size(),
                   " actual=", actual_hashes.size());
        all_ok = false;
    }

    // 逐 chunk 比对，定位损坏位置
    std::size_t min_count = (std::min)(expected_hashes.size(), actual_hashes.size());
    for (std::size_t i = 0; i < min_count; ++i) {
        if (expected_hashes[i] != actual_hashes[i]) {
            all_ok = false;
            LINOH_WARN("TensorReassembler: chunk hash mismatch at tensor_id=",
                       static_cast<unsigned long long>(tensor_id),
                       " shard_idx=", shard_idx,
                       " chunk_idx=", i);

            // 触发失败回调
            ChunkVerifyFailureCallback fail_cb;
            {
                std::lock_guard<std::mutex> lk(chunk_cb_mu_);
                fail_cb = chunk_failure_cb_;
            }
            if (fail_cb) {
                try {
                    fail_cb(tensor_id, shard_idx, i, expected_hashes[i], actual_hashes[i]);
                } catch (...) {
                    LINOH_ERROR("TensorReassembler: chunk verify failure callback threw exception");
                }
            }
        }
    }

    return all_ok;
}

// ============================================================================
// TensorStreamer
// ============================================================================

TensorStreamer::TensorStreamer(std::size_t shard_size, std::size_t parallel_streams)
    : shard_size_(shard_size), parallel_streams_(parallel_streams) {
    if (shard_size_ == 0) shard_size_ = 64 * 1024;
    if (parallel_streams_ == 0) parallel_streams_ = 4;
}

std::vector<TensorShardMessage> TensorStreamer::shard(
    std::uint64_t tensor_id,
    std::span<const std::uint8_t> data,
    TensorDType dtype,
    std::array<std::uint32_t, 4> shape) const {

    std::vector<TensorShardMessage> result;
    std::size_t total_bytes = data.size();
    if (total_bytes == 0) {
        // 空 tensor：生成 1 个空分片
        TensorShardMessage msg;
        msg.meta.tensor_id = tensor_id;
        msg.meta.total_shards = 1;
        msg.meta.shard_idx = 0;
        msg.meta.dtype = dtype;
        msg.meta.shape = shape;
        msg.meta.total_bytes = 0;
        msg.meta.shard_bytes = 0;
        msg.meta.is_last = true;
        msg.data = {};
        result.push_back(std::move(msg));
        return result;
    }

    std::uint32_t total_shards = static_cast<std::uint32_t>(shard_count(total_bytes));
    result.reserve(total_shards);

    std::size_t offset = 0;
    for (std::uint32_t idx = 0; idx < total_shards; ++idx) {
        std::size_t remaining = total_bytes - offset;
        std::size_t this_size = std::min(shard_size_, remaining);

        TensorShardMessage msg;
        msg.meta.tensor_id = tensor_id;
        msg.meta.total_shards = total_shards;
        msg.meta.shard_idx = idx;
        msg.meta.dtype = dtype;
        msg.meta.shape = shape;
        msg.meta.total_bytes = static_cast<std::uint64_t>(total_bytes);
        msg.meta.shard_bytes = static_cast<std::uint32_t>(this_size);
        msg.meta.is_last = (idx == total_shards - 1);
        msg.data.assign(data.begin() + offset, data.begin() + offset + this_size);

        result.push_back(std::move(msg));
        offset += this_size;
    }
    return result;
}

std::size_t TensorStreamer::shard_count(std::size_t total_bytes) const noexcept {
    if (total_bytes == 0) return 1;
    return (total_bytes + shard_size_ - 1) / shard_size_;
}

std::vector<std::vector<std::uint32_t>> TensorStreamer::assign_streams(
    std::uint32_t total_shards) const {
    std::vector<std::vector<std::uint32_t>> streams(parallel_streams_);
    for (std::uint32_t i = 0; i < total_shards; ++i) {
        streams[i % parallel_streams_].push_back(i);
    }
    return streams;
}

// ============================================================================
// v3.9.6 M17: TensorStreamer 逐 chunk sha256 计算
// ============================================================================

crypto::ChunkHashList TensorStreamer::compute_shard_chunk_hashes(
    std::span<const std::uint8_t> shard_data,
    std::size_t chunk_size) const {
    if (chunk_size == 0) {
        chunk_size = crypto::ChunkHasher::kDefaultChunkSize;
    }
    crypto::ChunkHasher hasher(chunk_size);
    return hasher.compute(shard_data);
}

ShardHashAnnouncePayload TensorStreamer::build_shard_hash_announce(
    std::uint64_t tensor_id,
    std::uint32_t shard_idx,
    std::span<const std::uint8_t> shard_data,
    std::size_t chunk_size) const {
    ShardHashAnnouncePayload announce;
    announce.tensor_id = tensor_id;
    announce.shard_idx = shard_idx;
    announce.chunk_size = static_cast<std::uint32_t>(
        chunk_size == 0 ? crypto::ChunkHasher::kDefaultChunkSize : chunk_size);
    announce.chunk_hashes = compute_shard_chunk_hashes(shard_data, chunk_size);
    return announce;
}

// ============================================================================
// 辅助函数
// ============================================================================

const char *dtype_name(TensorDType dt) noexcept {
    switch (dt) {
        case TensorDType::F32:  return "f32";
        case TensorDType::F16:  return "f16";
        case TensorDType::BF16: return "bf16";
        case TensorDType::I32:  return "i32";
        case TensorDType::U8:   return "u8";
        case TensorDType::F64:  return "f64";
        case TensorDType::I64:  return "i64";
        case TensorDType::I8:   return "i8";
    }
    return "unknown";
}

std::size_t dtype_size(TensorDType dt) noexcept {
    switch (dt) {
        case TensorDType::F32:  return 4;
        case TensorDType::F16:  return 2;
        case TensorDType::BF16: return 2;
        case TensorDType::I32:  return 4;
        case TensorDType::U8:   return 1;
        case TensorDType::F64:  return 8;
        case TensorDType::I64:  return 8;
        case TensorDType::I8:   return 1;
    }
    return 0;
}

}  // namespace linoh::multimodal
