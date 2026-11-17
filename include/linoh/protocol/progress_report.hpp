// progress_report.hpp — v4.3.0 M21 双层进度上报 payload
//
// 借鉴 Psyche Coordinator tick 进度上报 + iroh-blobs download progress，
// 在模型加载/大 tensor 传输时提供 overall + current_item 双层进度。
//
// 用途：
//   - win-worker 模型分片下载：overall=已下载 shard 数/总 shard 数，
//     current_item=当前 shard 文件名 + 已下载字节/总字节
//   - node-agent merged.gguf 合并：overall=已合并层数/总层数，
//     current_item=当前层 + 已写入字节/总字节
//   - 大 tensor 分片传输：overall=已发送 shard 数/总 shard 数，
//     current_item=tensor_id + 已发送字节/总字节
//
// 传输通道：ctrl/1 ALPN（控制面 Notification，request_id=0）
// MethodId: ProgressReport (0x0065)
//
// wire 格式（小端字节序）：
//   ┌─────────────────────┬─────────────────────┐
//   │ overall_current(4B) │ overall_total(4B)   │
//   ├─────────────────────┼─────────────────────┤
//   │ item_name_len(2B)   │ item_name(NB UTF-8) │
//   ├─────────────────────┼─────────────────────┤
//   │ item_bytes_done(8B) │ item_bytes_total(8B)│
//   └─────────────────────┴─────────────────────┘
//   最小 26B（item_name 空），最大 26+255B（item_name 限 255B 防滥用）
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace linoh::protocol {

/// 双层进度上报 payload（v4.3.0 M21）
struct ProgressReportPayload {
    // === overall 进度（整体） ===
    std::uint32_t overall_current{0};  ///< 已完成项数
    std::uint32_t overall_total{0};    ///< 总项数（0=未知/不可数）

    // === current_item 进度（当前正在处理的项） ===
    std::string item_name;             ///< 当前项名称（如 "layer_0028.gguf"），空=无当前项
    std::uint64_t item_bytes_done{0};  ///< 当前项已传输/处理字节
    std::uint64_t item_bytes_total{0}; ///< 当前项总字节（0=未知大小）

    // === 序列化 ===

    /// 序列化为字节流
    std::vector<std::uint8_t> serialize() const;

    /// 零拷贝序列化（append 到 out）
    std::size_t serialize_into(std::vector<std::uint8_t> &out) const;

    /// 计算序列化后的字节数（供预分配）
    std::size_t wire_size() const noexcept;

    // === 反序列化 ===

    /// 从字节流解析
    /// @return 解析成功返回 payload，数据不足或格式错误返回 nullopt
    static std::optional<ProgressReportPayload> parse(
        std::span<const std::uint8_t> data);

    // === 便捷方法 ===

    /// overall 完成百分比 [0.0, 1.0]，overall_total=0 时返回 0
    double overall_percent() const noexcept;

    /// current_item 完成百分比 [0.0, 1.0]，item_bytes_total=0 时返回 0
    double item_percent() const noexcept;

    // === 比较 ===
    bool operator==(const ProgressReportPayload &) const = default;
};

/// item_name 最大长度（字节），防滥用
/// v4.3.0 M21 fix: 从 255 提升到 512，支持长路径名（如 model shard 全路径）
constexpr std::size_t kProgressReportMaxItemNameLen = 512;

/// ProgressReportPayload 最小 wire 大小（item_name 为空）
constexpr std::size_t kProgressReportMinWireSize = 4 + 4 + 2 + 8 + 8;  // = 26

}  // namespace linoh::protocol
