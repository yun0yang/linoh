// payload_audit.cpp — v1.5.0.1 P0-1 payload 审计观测实现
//
// 仅观测，不修改任何行为。atomic 计数 + 1MB/1min 落盘周期。

#include "linoh/observability/payload_audit.hpp"

#include "linoh/util/logging.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <sstream>

namespace linoh {
namespace observability {

PayloadAuditor& PayloadAuditor::instance() {
    static PayloadAuditor inst;
    // v1.5.0.1: 首次访问时读环境变量注入 enable 状态和落盘目录
    static bool init_once = []() {
        if (is_audit_enabled_by_env()) {
            inst.enable(true);
            LINOH_DEBUG("PayloadAuditor: enabled via LINOH_AUDIT env");
        }
        if (const char* env = std::getenv("LINOH_AUDIT_DIR")) {
            if (env[0] != '\0') {
                inst.set_log_dir(std::string(env));
                LINOH_DEBUG("PayloadAuditor: log_dir from env = ", env);
            }
        }
        return true;
    }();
    (void)init_once;
    return inst;
}

bool is_audit_enabled_by_env() {
    const char* env = std::getenv("LINOH_AUDIT");
    return env && (std::string(env) == "1" || std::string(env) == "true");
}

void PayloadAuditor::record_payload_write(const PayloadAuditRecord& rec) {
    if (!enabled_.load()) return;

    // 1. 原子计数
    total_payload_bytes_.fetch_add(rec.payload_actual, std::memory_order_relaxed);
    if (rec.is_retx) {
        retx_write_count_.fetch_add(1, std::memory_order_relaxed);
    } else {
        normal_write_count_.fetch_add(1, std::memory_order_relaxed);
    }
    if (rec.short_write) {
        short_write_count_.fetch_add(1, std::memory_order_relaxed);
    }

    // 2. 序列化为 JSONL
    auto ts_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     rec.ts.time_since_epoch()).count();
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        R"({"type":"payload_write","conn":%llu,"stream":%llu,"declared":%zu,"actual":%zu,"space":%zu,"short":%s,"retx":%s,"ts":%lld})",
        (unsigned long long)rec.conn_id,
        (unsigned long long)rec.stream_id,
        rec.payload_declared,
        rec.payload_actual,
        rec.payload_space,
        rec.short_write ? "true" : "false",
        rec.is_retx ? "true" : "false",
        (long long)ts_ms);

    {
        std::lock_guard<std::mutex> lk(buffer_mu_);
        pending_buffer_.emplace_back(buf);
        pending_records_.fetch_add(1, std::memory_order_relaxed);
    }

    // 3. 1MB 触发落盘（v1.5.0.1 fix: 用 log_dir() 而非空串，触发自动注入目录）
    if (pending_records_.load() >= 1000) {
        flush_to_file(log_dir());
    }
}

void PayloadAuditor::record_sent_pkts_state(const SentPktsAuditRecord& rec) {
    if (!enabled_.load()) return;

    auto ts_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     rec.ts.time_since_epoch()).count();
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        R"({"type":"sent_pkts_state","conn":%llu,"sent_packets":%zu,"sent_payloads_bytes":%zu,"retx_queue":%zu,"retx_attempts":%zu,"force_retx":%s,"ts":%lld})",
        (unsigned long long)rec.conn_id,
        rec.sent_packets_size,
        rec.sent_payloads_bytes,
        rec.retx_queue_size,
        rec.retx_attempts_size,
        rec.force_retx ? "true" : "false",
        (long long)ts_ms);

    {
        std::lock_guard<std::mutex> lk(buffer_mu_);
        pending_buffer_.emplace_back(buf);
        pending_records_.fetch_add(1, std::memory_order_relaxed);
    }
}

void PayloadAuditor::flush_to_file(const std::string& log_dir) {
    std::vector<std::string> to_write;
    {
        std::lock_guard<std::mutex> lk(buffer_mu_);
        if (pending_buffer_.empty()) return;
        to_write.swap(pending_buffer_);
        pending_records_.store(0, std::memory_order_relaxed);
    }

    // 默认日志目录：./audit_payload_<timestamp>.log
    // v1.5.0.1 fix: 用 std::filesystem::absolute + create_directories 确保子目录存在
    // v1.5.0.1 fix: log_dir 为空时回退到 PayloadAuditor::log_dir_（LINOH_AUDIT_DIR env）
    std::filesystem::path dir;
    try {
        std::string effective_dir = log_dir;
        if (effective_dir.empty()) {
            std::lock_guard<std::mutex> lk(dir_mu_);
            effective_dir = log_dir_;
        }
        if (effective_dir.empty()) {
            dir = std::filesystem::current_path();
        } else {
            dir = std::filesystem::absolute(effective_dir);
        }
        // 确保目录存在
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) {
            LINOH_WARN("PayloadAuditor: create_directories failed: ", ec.message());
            return;
        }
    } catch (const std::exception& e) {
        LINOH_WARN("PayloadAuditor: path error: ", e.what());
        return;
    }
    auto t = std::time(nullptr);
    char ts_buf[32];
    std::strftime(ts_buf, sizeof(ts_buf), "%Y%m%d_%H%M%S", std::localtime(&t));
    std::filesystem::path path = dir / ("audit_payload_" + std::string(ts_buf) + ".log");

    std::ofstream ofs(path, std::ios::app);
    if (!ofs.is_open()) {
        LINOH_WARN("PayloadAuditor: failed to open ", path.string());
        return;
    }
    for (const auto& line : to_write) {
        ofs << line << "\n";
    }
    ofs.close();
    LINOH_DEBUG("PayloadAuditor: flushed ", to_write.size(), " records to ", path.string());
}

void PayloadAuditor::reset_stats() {
    short_write_count_.store(0, std::memory_order_relaxed);
    retx_write_count_.store(0, std::memory_order_relaxed);
    normal_write_count_.store(0, std::memory_order_relaxed);
    total_payload_bytes_.store(0, std::memory_order_relaxed);
    pending_records_.store(0, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lk(buffer_mu_);
    pending_buffer_.clear();
}

}  // namespace observability
}  // namespace linoh
