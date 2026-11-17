// payload_audit.hpp — v1.5.0.1 P0-1 payload 写入审计观测
//
// 背景：v1.5.0 retx 链路断链导致 32MB 跨节点 OOS 永久卡死。本模块仅观测
// build_1rtt_packet 中 payload 写入的统计分布，用于：
//   1. 验证 P0-1 retx 修复后是否仍有 payload 写入异常
//   2. 跟踪 process_stream / retx 块的写入分布（短写/正常）
//   3. 观测 sent_packets_ + sent_payloads_ 状态（map 大小、字节数）
//
// 设计原则：
//   - 只读不改：审计点不修改任何行为，仅记录统计
//   - 低开销：atomic 计数，1MB/1min 落盘周期
//   - 可关闭：默认关闭，通过环境变量 LINOH_AUDIT=1 启用
//
// 输出格式：JSONL（每行一个 JSON 对象），可直接被 Loki/ES 消费
//
// 关联 BUG：v1.5.0 重传机制断链 P0-1（commit f5f7297 已修，本模块观测修复后效果）

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

namespace linoh {
namespace observability {

/// 单次 payload 写入审计记录
struct PayloadAuditRecord {
    std::uint64_t conn_id;            // 连接 ID
    std::uint64_t stream_id;          // 流 ID（0 表示非流数据，如 retx 块）
    std::size_t payload_declared;     // 调用方声明的 payload 大小
    std::size_t payload_actual;       // 实际写入 mbuf 的字节数
    std::size_t payload_space;        // 进入函数时计算的可用空间
    bool short_write;                 // actual < declared
    bool is_retx;                     // 是否来自 retx 块
    std::chrono::steady_clock::time_point ts;
};

/// sent_packets_ / sent_payloads_ 状态审计（每 10 秒采样一次）
struct SentPktsAuditRecord {
    std::uint64_t conn_id;
    std::size_t sent_packets_size;     // sent_packets_ 当前条目数
    std::size_t sent_payloads_bytes;   // sent_payloads_ 当前字节数
    std::size_t retx_queue_size;       // retransmit_queue_ 当前条目数
    std::size_t retx_attempts_size;    // retx_attempts_ 当前条目数
    bool force_retx;                   // force_retx_ 标志
    std::chrono::steady_clock::time_point ts;
};

/// 全局审计器（单例）
class PayloadAuditor {
public:
    static PayloadAuditor& instance();

    /// 启用/禁用审计
    void enable(bool on = true) { enabled_.store(on); }
    bool is_enabled() const { return enabled_.load(); }

    /// 设置落盘目录（空 = current_path）
    void set_log_dir(std::string dir) {
        std::lock_guard<std::mutex> lk(dir_mu_);
        log_dir_ = std::move(dir);
    }
    const std::string& log_dir() const {
        std::lock_guard<std::mutex> lk(dir_mu_);
        return log_dir_;
    }

    /// 记录单次 payload 写入
    void record_payload_write(const PayloadAuditRecord& rec);

    /// 记录 sent_packets_ 状态采样
    void record_sent_pkts_state(const SentPktsAuditRecord& rec);

    /// 落盘到 JSONL 文件（线程安全）
    void flush_to_file(const std::string& log_dir);

    /// 统计：累计 short_write 次数
    std::uint64_t short_write_count() const { return short_write_count_.load(); }
    /// 统计：累计 retx 块写入次数
    std::uint64_t retx_write_count() const { return retx_write_count_.load(); }
    /// 统计：累计正常写入次数
    std::uint64_t normal_write_count() const { return normal_write_count_.load(); }
    /// 统计：累计 payload 写入字节数
    std::uint64_t total_payload_bytes() const { return total_payload_bytes_.load(); }

    /// 重置所有统计
    void reset_stats();

private:
    PayloadAuditor() = default;
    ~PayloadAuditor() = default;
    PayloadAuditor(const PayloadAuditor&) = delete;
    PayloadAuditor& operator=(const PayloadAuditor&) = delete;

    std::atomic<bool> enabled_{false};
    std::atomic<std::uint64_t> short_write_count_{0};
    std::atomic<std::uint64_t> retx_write_count_{0};
    std::atomic<std::uint64_t> normal_write_count_{0};
    std::atomic<std::uint64_t> total_payload_bytes_{0};
    std::atomic<std::uint64_t> last_flush_ts_ms_{0};
    std::atomic<std::size_t> pending_records_{0};

    std::mutex buffer_mu_;
    std::vector<std::string> pending_buffer_;  // 序列化的 JSONL 记录

    // 落盘目录（v1.5.0.1 增补：支持 LINOH_AUDIT_DIR env 注入）
    mutable std::mutex dir_mu_;
    std::string log_dir_;
};

/// 检查环境变量 LINOH_AUDIT 是否启用
bool is_audit_enabled_by_env();

}  // namespace observability
}  // namespace linoh
