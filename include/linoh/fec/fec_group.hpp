// fec_group.hpp — FEC Group 前向纠错组包/解包（P5-B-1 Step 2）
//
// 背景：
//   - fec.hpp 提供底层 FecEncoder/FecDecoder（K 数据块 → K+M 网络包 → 接收 K 个）
//   - FecGroup 把大块数据切片为 K 个数据块并 FEC 编码为 K+M 个网络包
//   - FecGroupReceiver 接收 K+M 个网络包（带 group_id），丢失 ≤ M 时自动恢复
//   - 与 STREAM 帧解耦，可独立嵌入 PP 推理链路（hidden_state / 图片 / 视频特征）
//
// 协议包格式（FecPacket，序列化到字节流）：
//   | group_id (4B) | block_idx (1B) | block_size (2B) | block_data (block_size B) |
//
// 设计原则：
//   - 发送端：FecGroup::pack(data) → vector<FecPacket>
//   - 接收端：FecGroupReceiver::feed(packet) → on_complete callback when group done
//   - 支持多 group 并发：按 group_id 分别管理
//   - 超时清理：超过 TTL 的 group 自动丢弃
//   - 乱序到达：按 (group_id, block_idx) 索引
//   - 限制 group 数量防止内存爆炸（max_inflight_groups）

#pragma once

#include "linoh/fec/fec.hpp"

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace linoh::fec {

/// FEC 网络包
struct FecPacket {
    std::uint32_t group_id{0};    // 组 ID（同一组数据共享）
    std::uint8_t  block_idx{0};   // 块索引（0..K+M-1）
    std::uint16_t block_size{0};  // 块大小（字节）
    std::vector<std::uint8_t> data;  // 块数据
};

/// 序列化 FecPacket → 字节流
std::vector<std::uint8_t> serialize_packet(const FecPacket &p);

/// 反序列化 字节流 → FecPacket
std::optional<FecPacket> deserialize_packet(std::span<const std::uint8_t> bytes);

/// FEC 发送端：把任意大小数据切片 + FEC 编码为 K+M 个包
class FecGroup {
public:
    /// 构造：用 ChannelConfig 派生 FecConfig
    explicit FecGroup(FecConfig cfg);

    /// 编码数据为 K+M 个网络包
    /// \param group_id 组 ID（调用方分配，需保证唯一）
    /// \param data 输入数据（任意大小，自动按 block_size 切片，最后一块可小于 block_size）
    /// \return K+M 个 FecPacket
    std::vector<FecPacket> pack(std::uint32_t group_id, std::span<const std::uint8_t> data);

    /// 访问配置
    const FecConfig &config() const noexcept { return cfg_; }

    /// K（数据块数）
    std::size_t data_blocks() const noexcept { return cfg_.data_blocks; }

    /// K+M（总块数）
    std::size_t total_blocks() const noexcept { return cfg_.data_blocks + cfg_.recovery_blocks; }

private:
    FecConfig cfg_;
    std::unique_ptr<FecEncoder> encoder_;
};

/// FEC 接收端
class FecGroupReceiver {
public:
    struct Options {
        std::size_t max_inflight_groups{1024};  // 最大并发 group 数
        std::chrono::milliseconds ttl{60000};   // group 超时时间
    };

    /// 完成的 group 回调
    using CompleteCallback = std::function<void(std::uint32_t group_id,
                                                std::vector<std::uint8_t> recovered_data,
                                                std::size_t missing_blocks /* 丢失块数 */)>;

    // [GCC 11.4 compat] 拆为两个重载，避免 `Options opts = {}` brace-enclosed
    // initializer list 转换失败（与类内默认成员初始化器冲突 [class.mem]/6）。
    explicit FecGroupReceiver(FecConfig cfg);
    explicit FecGroupReceiver(FecConfig cfg, Options opts);

    /// 喂入一个包（thread-safe）
    /// 同一 group_id 的 K+M 个包到齐（或丢失 ≤ M）时触发 complete 回调
    void feed(FecPacket packet);

    /// 设置回调
    void set_complete_callback(CompleteCallback cb) { on_complete_ = std::move(cb); }

    /// 清理超时 group（建议定时调用）
    /// \return 被清理的 group 数
    std::size_t cleanup_expired();

    /// 统计：当前 in-flight group 数
    std::size_t inflight_count() const;

    /// 访问配置
    const FecConfig &config() const noexcept { return cfg_; }

private:
    struct GroupState {
        std::uint32_t group_id;
        std::size_t data_blocks;     // K
        std::size_t recovery_blocks; // M
        std::size_t block_size;      // 块大小（用于恢复时切分）
        std::size_t total_size;      // 原始数据总大小（最后一块可能 < block_size）
        std::vector<std::optional<std::vector<std::uint8_t>>> received;  // K+M 个槽位
        std::chrono::steady_clock::time_point created_at;
        bool completed{false};
        // mp-P11 (v1.7.0.8): 维护 received_count，避免 feed 时每次 O(K+M) 扫描统计 missing
        std::size_t received_count{0};
    };

    FecConfig cfg_;
    Options opts_;
    std::unique_ptr<FecDecoder> decoder_;
    CompleteCallback on_complete_;

    mutable std::mutex mu_;
    std::unordered_map<std::uint32_t, GroupState> groups_;
    // mp-M4 (v1.7.0.8): completed_ids_ 配合 completed_order_ 实现 FIFO 有界淘汰，
    //   防止长期运行 completed_ids_ 无限增长（每个完成的 group_id 永久驻留 set）。
    //   completed_order_ 保留插入顺序，超 kMaxCompletedIds 时从队首弹出最旧条目。
    std::unordered_set<std::uint32_t> completed_ids_;  // 已完成 group_id 集合（防重复触发）
    std::deque<std::uint32_t> completed_order_;        // FIFO 顺序，配合 set 淘汰
    static constexpr std::size_t kMaxCompletedIds = 4096;  // 上限，超限淘汰最旧
};

}  // namespace linoh::fec
