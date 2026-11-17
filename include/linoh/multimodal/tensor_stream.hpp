// tensor_stream.hpp — 大 tensor 分片 + 重组（P5-A-3）
//
// 借鉴 Sunshine RTP 包分片（frameIdx + streamIdx + lastPayloadLen）思想：
//   - 大 tensor（MB/GB 级）按固定大小分片（默认 64KB），避免 QUIC 单 stream HoL blocking
//   - 多 stream 并行发送（默认 4），充分利用多路径带宽
//   - 接收端按 tensor_id 重组，乱序到达正确拼装
//   - 单 shard 丢失可触发重传（上层通过 TensorShardAck 实现）
//
// 设计原则：
//   - 分片/重组逻辑独立于网络层，可在内存中测试
//   - TensorMeta 固定头部 48 字节，便于 parse
//   - 不依赖 sync_t<T>（P5-C 阶段才引入），用 std::mutex
//   - 实际网络发送由上层调用 conn->notify(TensorShard, payload) 完成
//   - TensorStreamer 不直接持有 Connection（解耦，便于测试）
//
// 与 P5-A-1 的关系：
//   - tensor 数据走 data_conn（ALPN=pp-*/1）
//   - 控制信息（TensorCancel）走 ctrl_conn（ALPN=ctrl/1，通过 ControlChannel）

#pragma once

#include "linoh/crypto/chunk_hash.hpp"  // v3.9.6 M17: ChunkHasher, ChunkHashList

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace linoh::multimodal {

/// Tensor 数据类型（uint8 编码）
enum class TensorDType : std::uint8_t {
    F32  = 0,  // float32
    F16  = 1,  // float16
    BF16 = 2,  // bfloat16
    I32  = 3,  // int32
    U8   = 4,  // uint8
    F64  = 5,  // float64
    I64  = 6,  // int64
    I8   = 7,  // int8
};

/// Tensor 元数据（每个分片都携带，便于乱序重组）
///
/// 序列化布局（48 字节固定头部，小端序）：
///   [0..7]   tensor_id      u64
///   [8..11]  total_shards   u32
///   [12..15] shard_idx      u32
///   [16]     dtype          u8
///   [17..18] reserved       2B（对齐）
///   [19..34] shape[4]       4×u32
///   [35..42] total_bytes    u64
///   [43..46] shard_bytes    u32
///   [47]     is_last        u8 (0/1)
///
/// v3.8.4: merkle_root 为内存字段，不参与 48B 序列化（向后兼容）。
///   merkle_root 通过 TensorReassembler::set_expected_merkle_root() 带外设置，
///   由上层 ControlChannel 的 TensorMerkleAnnounce 消息下发。
struct TensorMeta {
    std::uint64_t tensor_id{0};                       // 唯一标识
    std::uint32_t total_shards{0};                    // 总分片数
    std::uint32_t shard_idx{0};                       // 当前分片序号（0-based）
    TensorDType   dtype{TensorDType::F32};            // 数据类型
    std::array<std::uint32_t, 4> shape{0, 0, 0, 0};   // 最多 4 维（0 表示无此维）
    std::uint64_t total_bytes{0};                     // 原始 tensor 字节数
    std::uint32_t shard_bytes{0};                     // 当前分片字节数
    bool          is_last{false};                     // 是否最后一片

    /// v3.8.4: Merkle Root（32 字节，默认全零=未设置）
    /// 不参与 serialize/parse（48B 头部不变），通过带外方式传递
    std::array<std::uint8_t, 32> merkle_root{};

    /// 序列化为 48 字节（不含 merkle_root，向后兼容）
    std::array<std::uint8_t, 48> serialize() const;
    /// 从字节流反序列化，返回是否成功（merkle_root 保持默认全零）
    static bool parse(std::span<const std::uint8_t> data, TensorMeta &out);

    /// v3.8.4: 判断 merkle_root 是否已设置（非全零）
    bool has_merkle_root() const noexcept;
};

/// Tensor 分片消息（= TensorMeta + shard data）
struct TensorShardMessage {
    TensorMeta meta;
    std::vector<std::uint8_t> data;  // 分片数据（meta.shard_bytes 字节）

    /// 序列化为字节流（48B 头 + data）
    std::vector<std::uint8_t> serialize() const;
    /// 从字节流反序列化
    static bool parse(std::span<const std::uint8_t> data, TensorShardMessage &out);
};

/// v3.9.6 M17: Shard Hash 公告消息（带外传递，走 ctrl/1 ALPN）
///
/// 发送端在发送 TensorShard 之前/之后，通过 ControlChannel 发送此消息，
/// 接收端据此对收到的 shard 数据进行逐 chunk 校验，定位损坏的具体 chunk。
///
/// 序列化布局（20 字节固定头部 + 可变 hash 数据，小端序）：
///   [0..7]   tensor_id    u64
///   [8..11]  shard_idx    u32
///   [12..15] chunk_size   u32  （计算 chunk hash 时的 chunk 大小）
///   [16..19] chunk_count  u32  （chunk hash 数量）
///   [20..]   chunk_hashes       （32 * chunk_count 字节，拼接的 sha256 列表）
///
/// 与 v3.8.4 Merkle Root 的关系：
///   - Merkle Root 是 tensor 级整体校验（所有 shard 到齐后一次性校验）
///   - ShardHashAnnounce 是 shard 级细粒度校验（每收到一个 shard 边校验）
///   - 两者互补：Merkle Root 防整体篡改，chunk hash 定位损坏位置
struct ShardHashAnnouncePayload {
    std::uint64_t tensor_id{0};        // 关联的 tensor ID
    std::uint32_t shard_idx{0};        // 关联的 shard 序号
    std::uint32_t chunk_size{0};       // chunk 大小（字节）
    crypto::ChunkHashList chunk_hashes;  // chunk sha256 列表

    /// 序列化为字节流（20B 头 + 32 * chunk_hashes.size() 字节）
    std::vector<std::uint8_t> serialize() const;
    /// 从字节流反序列化，返回是否成功
    static bool parse(std::span<const std::uint8_t> data, ShardHashAnnouncePayload &out);

    /// 固定头部大小
    static constexpr std::size_t kHeaderSize = 20;
};

/// Tensor 重组状态
struct TensorReassemblyState {
    TensorMeta first_meta;                    // 首个分片的元数据（用于查询 total_bytes/shape）
    std::map<std::uint32_t, std::vector<std::uint8_t>> shards;  // shard_idx → data（按 idx 排序便于顺序拼接）
    std::uint32_t received_count{0};          // 已接收分片数（含重复，去重后）
    bool first_received{false};               // 是否已收到任何分片
    std::chrono::steady_clock::time_point first_seen_time{};  // v1.5 P1-3: 首个分片接收时间，用于超时自动清理
};

/// Tensor 重组器（接收端）
///
/// 用法：
///   TensorReassembler reasm;
///   reasm.on_complete([](uint64_t id, vector<uint8_t> data, TensorMeta meta) {
///       // 所有分片到齐
///   });
///   reasm.on_shard(shard_msg);  // 每收到一个分片调用
class TensorReassembler {
public:
    using CompleteCallback = std::function<void(std::uint64_t tensor_id,
                                                std::vector<std::uint8_t> data,
                                                TensorMeta meta)>;

    /// 默认自动清理超时（v1.5 P1-3）
    /// sender 异常退出未发完 shard 时，receiver 端 buffers_ 持续膨胀
    /// 默认 60s 后自动 cleanup，避免内存泄漏
    static constexpr std::chrono::seconds kDefaultAutoCleanupTimeout{60};

    /// 注册完成回调
    void on_complete(CompleteCallback cb);

    /// 处理收到的分片
    /// \return true=该分片被接受（新分片），false=被拒绝（重复/无效）
    bool on_shard(const TensorShardMessage &shard);

    /// 查询某个 tensor 的重组进度（0.0~1.0）
    float progress(std::uint64_t tensor_id) const;

    /// 当前正在重组的 tensor 数量
    std::size_t pending_count() const;

    /// 获取某个 tensor 的重组状态（const，用于测试）
    std::optional<TensorReassemblyState> state(std::uint64_t tensor_id) const;

    /// 清理已完成的 tensor 重组状态（回调后自动调用）
    void cleanup(std::uint64_t tensor_id);

    /// 清空所有重组状态
    void clear();

    /// v1.5 P1-3: 设置自动清理超时（秒级）
    void set_auto_cleanup_timeout(std::chrono::seconds t);

    /// v1.5 P1-3: 设置自动清理超时（毫秒级，便于测试用短超时）
    void set_auto_cleanup_timeout_ms(std::chrono::milliseconds t);

    /// v1.5 P1-3: 获取自动清理超时（秒级整数）
    std::chrono::seconds auto_cleanup_timeout() const;

    /// v1.5 P1-3: 手动触发一次超时清理（返回被清理的 tensor 数）
    std::size_t run_auto_cleanup();

    // ===== v3.8.4: Merkle Root 完整性校验 =====

    /// Merkle 校验失败回调类型
    /// @param tensor_id 校验失败的 tensor ID
    /// @param expected_root 期望的 Merkle Root
    /// @param actual_root 实际计算的 Merkle Root
    using MerkleFailureCallback = std::function<void(
        std::uint64_t tensor_id,
        const std::array<std::uint8_t, 32> &expected_root,
        const std::array<std::uint8_t, 32> &actual_root)>;

    /// v3.8.4: 设置某个 tensor 的期望 Merkle Root（带外传递，由上层 ControlChannel 下发）
    /// @note merkle_root 全零表示该 tensor 无需校验（向后兼容）
    void set_expected_merkle_root(std::uint64_t tensor_id,
                                   const std::array<std::uint8_t, 32> &merkle_root);

    /// v3.8.4: 清除某个 tensor 的期望 Merkle Root
    void clear_expected_merkle_root(std::uint64_t tensor_id);

    /// v3.8.4: 启用/禁用 Merkle 校验（默认 false，向后兼容）
    void set_verify_merkle(bool enable) noexcept;

    /// v3.8.4: 查询 Merkle 校验是否启用
    bool verify_merkle_enabled() const noexcept;

    /// v3.8.4: 启用/禁用中间节点校验（默认 false，仅末节点 is_last=true 校验）
    /// @note PP 菊花链中间节点默认不校验，保持低延迟（M17 风险对策）
    void set_mid_hop_verify(bool enable) noexcept;

    /// v3.8.4: 查询中间节点校验是否启用
    bool mid_hop_verify_enabled() const noexcept;

    /// v3.8.4: 注册 Merkle 校验失败回调
    /// @note 回调在完成回调前触发；校验失败时不触发 CompleteCallback，改为触发此回调
    void on_merkle_failure(MerkleFailureCallback cb);

    // ===== v3.9.6 M17: 逐 chunk 增量校验（sha256）=====

    /// chunk 校验失败回调类型
    /// @param tensor_id 校验失败的 tensor ID
    /// @param shard_idx 校验失败的 shard 序号
    /// @param chunk_idx 校验失败的 chunk 序号（0-based）
    /// @param expected 期望的 chunk sha256
    /// @param actual   实际计算的 chunk sha256
    using ChunkVerifyFailureCallback = std::function<void(
        std::uint64_t tensor_id,
        std::uint32_t shard_idx,
        std::size_t chunk_idx,
        const crypto::ChunkHash &expected,
        const crypto::ChunkHash &actual)>;

    /// M17: 设置某个 shard 的期望 chunk hash 列表（带外传递，由 ShardHashAnnounce 下发）
    /// @param chunk_size 计算 chunk hash 时的 chunk 大小（来自 ShardHashAnnouncePayload.chunk_size）
    /// @note hash 列表为空表示该 shard 无需 chunk 校验（向后兼容）
    void set_expected_chunk_hashes(std::uint64_t tensor_id,
                                    std::uint32_t shard_idx,
                                    std::uint32_t chunk_size,
                                    crypto::ChunkHashList hashes);

    /// M17: 清除某个 shard 的期望 chunk hash
    void clear_expected_chunk_hashes(std::uint64_t tensor_id, std::uint32_t shard_idx);

    /// M17: 清除某个 tensor 所有 shard 的期望 chunk hash
    void clear_tensor_chunk_hashes(std::uint64_t tensor_id);

    /// M17: 启用/禁用逐 chunk 校验（默认 false，向后兼容）
    void set_verify_chunk_hashes(bool enable) noexcept;

    /// M17: 查询逐 chunk 校验是否启用
    bool verify_chunk_hashes_enabled() const noexcept;

    /// M17: 注册 chunk 校验失败回调
    /// @note 回调在 on_shard 中触发（shard 接受后、完成回调前）；
    ///       校验失败时 shard 仍被接受（上层决定是否丢弃），但失败被记录
    void on_chunk_verify_failure(ChunkVerifyFailureCallback cb);

private:
    // mp-P9 (v1.7.0.9): 分桶锁重构
    //   原单一 mu_ 保护全部 buffers_，多 tensor 并发重组时锁竞争严重。
    //   改为 16 桶独立 mutex，按 tensor_id & 15 路由，不同桶可并行。
    //   桶数 16 是 2 的幂，位运算分桶高效；覆盖 100+ 并发 tensor 场景。
    //   外部 API 完全不变，纯内部重构。
    static constexpr std::size_t kNumBuckets = 16;
    static_assert((kNumBuckets & (kNumBuckets - 1)) == 0, "must be power of 2");

    struct Bucket {
        mutable std::mutex mu;
        std::unordered_map<std::uint64_t, TensorReassemblyState> buffers;
        // mp-P3 节流计时器移到桶级：每桶独立节流，扫描范围从 N 降到 N/16
        std::chrono::steady_clock::time_point last_cleanup_time{};
    };

    // 桶数组（Bucket 含 mutex 不可拷贝，std::array 默认构造可行）
    std::array<Bucket, kNumBuckets> buckets_;

    // 全局驱逐记录（防 late-arriving shard 重建），独立锁保护
    //   写频率低（仅超时清理时追加），读频率：每次 on_shard 检查
    //   锁顺序规则：evicted_mu_ 必须在 bucket.mu 之前获取（核心防死锁规则）
    //   绝不在持 bucket.mu 时获取 evicted_mu_
    std::mutex evicted_mu_;
    std::vector<std::pair<std::uint64_t, std::chrono::steady_clock::time_point>> recent_evicted_;
    static constexpr std::size_t kMaxRecentEvicted = 256;  // 上限，超限淘汰最旧

    // 回调独立锁（回调在桶锁外触发，避免死锁）
    std::mutex callback_mu_;
    CompleteCallback callback_;
    // mp-P9: 原子标志，标记是否已注册回调
    //   用于 on_shard 桶锁内快速判断是否应 erase 已完成 tensor，
    //   避免在持桶锁时获取 callback_mu_ 造成锁嵌套。
    //   语义：有回调→erase（防 late shard 重建）；无回调→保留（便于 state() 查询）
    std::atomic<bool> has_callback_{false};

    // 配置独立锁（低频读写，mutable 以支持 const 方法 auto_cleanup_timeout()）
    mutable std::mutex config_mu_;
    std::chrono::seconds auto_cleanup_timeout_{kDefaultAutoCleanupTimeout};  // v1.5 P1-3
    std::chrono::milliseconds ms_residue_{0};  // v1.5 P1-3: 毫秒尾数（<1s 精度）

    // ===== v3.8.4: Merkle 校验配置 =====
    std::atomic<bool> verify_merkle_enabled_{false};   // 默认 false，向后兼容
    std::atomic<bool> mid_hop_verify_enabled_{false};   // 默认 false，仅末节点校验
    mutable std::mutex merkle_roots_mu_;                // 保护 expected_merkle_roots_
    std::unordered_map<std::uint64_t, std::array<std::uint8_t, 32>> expected_merkle_roots_;
    std::mutex merkle_cb_mu_;                           // 保护 merkle_failure_cb_
    MerkleFailureCallback merkle_failure_cb_;

    // ===== v3.9.6 M17: 逐 chunk 校验配置 =====
    // key = (tensor_id << 32) | shard_idx，value = (chunk_size, chunk_hashes)
    //   tensor_id 为 u64，shard_idx 为 u32，组合为 u64 key 便于单层 map 查找
    std::atomic<bool> verify_chunk_hashes_enabled_{false};  // 默认 false，向后兼容
    mutable std::mutex chunk_hashes_mu_;                    // 保护 expected_chunk_hashes_
    std::unordered_map<std::uint64_t,
                       std::pair<std::uint32_t, crypto::ChunkHashList>>
        expected_chunk_hashes_;                             // key → (chunk_size, hashes)
    std::mutex chunk_cb_mu_;                                // 保护 chunk_failure_cb_
    ChunkVerifyFailureCallback chunk_failure_cb_;

    /// M17: 组合 chunk hash map 的 key
    static std::uint64_t chunk_hash_key_(std::uint64_t tensor_id,
                                          std::uint32_t shard_idx) noexcept {
        return (tensor_id << 32) | static_cast<std::uint64_t>(shard_idx);
    }

    /// M17: 校验单个 shard 的 chunk 哈希（锁外调用，触发失败回调）
    /// @return true 校验通过或无需校验；false 校验失败
    bool verify_shard_chunks_(std::uint64_t tensor_id,
                               std::uint32_t shard_idx,
                               std::span<const std::uint8_t> shard_data);

    // mp-P3 节流间隔（保留全局常量，桶级计时器使用）
    //   间隔选 100ms：1000 片/s 下扫描频率从 1000 次/s 降到 10 次/s（100 倍提升），
    //   同时兼容测试中 300ms sleep 后 on_shard 仍能触发清理。
    static constexpr std::chrono::milliseconds kCleanupIntervalMs{100};

    /// 桶选择函数（位运算，O(1)）
    std::size_t bucket_index(std::uint64_t tensor_id) const noexcept {
        return static_cast<std::size_t>(tensor_id) & (kNumBuckets - 1);
    }

    /// v3.8.4: 判断是否应对该 tensor 执行 Merkle 校验
    /// @note 必须同时满足：verify_merkle_enabled_ && 该 tensor 有 expected_root
    ///       && (is_last || mid_hop_verify_enabled_)
    bool should_verify_merkle_(std::uint64_t tensor_id, bool is_last) const;

    /// v3.8.4: 获取某个 tensor 的期望 Merkle Root（拷贝返回，线程安全）
    /// @return true 若该 tensor 有期望 root；false 若无（全零或不存在）
    bool get_expected_root_(std::uint64_t tensor_id,
                             std::array<std::uint8_t, 32> &out) const;

    /// 桶内清理（持桶锁调用，收集 expired_tid 到 expired_out）
    /// 注意：调用方持 bucket.mu，本函数不再加 evicted_mu_（由调用方锁外追加）
    void cleanup_bucket_locked_(Bucket &bucket,
                                std::chrono::steady_clock::time_point now,
                                std::chrono::seconds timeout_s,
                                std::chrono::milliseconds ms_res,
                                std::vector<std::uint64_t> &expired_out);

    /// 检查所有分片是否到齐，若到齐则触发回调
    void maybe_complete(std::uint64_t tensor_id);
};

/// Tensor 分片器（发送端）
///
/// 用法：
///   TensorStreamer streamer(64 * 1024, 4);  // 64KB/分片，4 stream 并行
///   auto shards = streamer.shard(tensor_id, data, dtype, shape);
///   for (auto &shard : shards) {
///       conn->notify(MethodId::TensorShard, shard.serialize());
///   }
class TensorStreamer {
public:
    /// 构造
    /// \param shard_size 分片大小（字节，默认 64KB）
    /// \param parallel_streams 并行 stream 数（默认 4，用于计算轮询发送顺序）
    TensorStreamer(std::size_t shard_size = 64 * 1024,
                   std::size_t parallel_streams = 4);

    /// 分片一个完整 tensor
    /// \param tensor_id 唯一标识
    /// \param data 原始 tensor 数据
    /// \param dtype 数据类型
    /// \param shape 形状（最多 4 维，0 表示无此维）
    /// \return 分片列表（按 shard_idx 顺序排列）
    std::vector<TensorShardMessage> shard(
        std::uint64_t tensor_id,
        std::span<const std::uint8_t> data,
        TensorDType dtype = TensorDType::F32,
        std::array<std::uint32_t, 4> shape = {0, 0, 0, 0}) const;

    /// 计算分片数量
    std::size_t shard_count(std::size_t total_bytes) const noexcept;

    /// 获取分片大小
    std::size_t shard_size() const noexcept { return shard_size_; }

    /// 获取并行 stream 数
    std::size_t parallel_streams() const noexcept { return parallel_streams_; }

    /// 按 parallel_streams 轮询分配 shard 到不同 stream
    /// 返回 stream_id → shard_idx 列表映射
    std::vector<std::vector<std::uint32_t>> assign_streams(
        std::uint32_t total_shards) const;

    // ===== v3.9.6 M17: 逐 chunk sha256 计算 =====

    /// M17: 计算单个 shard 数据的 chunk hash 列表
    /// @param shard_data shard 原始字节
    /// @param chunk_size chunk 大小（字节），0 表示用 ChunkHasher 默认值（16KiB）
    /// @return chunk sha256 列表（长度 = ceil(shard_data.size() / chunk_size)）
    crypto::ChunkHashList compute_shard_chunk_hashes(
        std::span<const std::uint8_t> shard_data,
        std::size_t chunk_size = 0) const;

    /// M17: 构建 ShardHashAnnounce 消息（带外公告某个 shard 的 chunk hash）
    /// @param tensor_id 关联的 tensor ID
    /// @param shard_idx shard 序号
    /// @param shard_data shard 原始字节
    /// @param chunk_size chunk 大小（字节），0 表示用 ChunkHasher 默认值
    /// @return ShardHashAnnouncePayload，可通过 ControlChannel 带外发送
    ShardHashAnnouncePayload build_shard_hash_announce(
        std::uint64_t tensor_id,
        std::uint32_t shard_idx,
        std::span<const std::uint8_t> shard_data,
        std::size_t chunk_size = 0) const;

private:
    std::size_t shard_size_;
    std::size_t parallel_streams_;
};

/// dtype 名称（用于日志/调试）
const char *dtype_name(TensorDType dt) noexcept;

/// dtype 字节数（每个元素的字节大小），返回 0 表示未知
std::size_t dtype_size(TensorDType dt) noexcept;

}  // namespace linoh::multimodal
