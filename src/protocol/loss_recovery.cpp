// linoh/protocol/loss_recovery.cpp — QUIC 丢包检测 + NewReno 重传实现

#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <unordered_set>

namespace linoh::protocol {

// ============================================================================
// RttEstimator
// ============================================================================

RttEstimator::RttEstimator()
    : srtt_ms_(kInitialRttMs)
    , rttvar_ms_(kInitialRttMs / 2.0)
    , rto_ms_(srtt_ms_ + 4 * rttvar_ms_)
    , first_sample_(true) {}

void RttEstimator::update(double latest_rtt_ms, double ack_delay_ms) {
    // P9.1: 跨线程读写保护（recv_thread 更新 / timeout+send 线程读取）
    std::lock_guard<std::mutex> lk(rtt_mu_);

    // RFC 9002 §5.2:
    // adjusted_rtt = latest_rtt - ack_delay (if not first sample)
    // if first sample: SRTT = latest_rtt, RTTVAR = latest_rtt/2

    double adjusted_rtt = latest_rtt_ms;

    // 仅当 adjusted_rtt < SRTT 时才减去 ack_delay
    // (否则对端可能低估了 delay，减去后会得到负值)
    if (!first_sample_ && ack_delay_ms > 0 && latest_rtt_ms >= srtt_ms_ + ack_delay_ms) {
        adjusted_rtt = latest_rtt_ms - ack_delay_ms;
    }

    if (first_sample_) {
        srtt_ms_ = adjusted_rtt;
        rttvar_ms_ = adjusted_rtt / 2.0;
        first_sample_ = false;
    } else {
        rttvar_ms_ = (1.0 - kBeta) * rttvar_ms_ + kBeta * std::abs(srtt_ms_ - adjusted_rtt);
        srtt_ms_ = (1.0 - kAlpha) * srtt_ms_ + kAlpha * adjusted_rtt;
    }

    // RTO = SRTT + 4 * RTTVAR, 限制在 [200ms, 60s]
    rto_ms_ = std::clamp(srtt_ms_ + 4.0 * rttvar_ms_, kRtoMinMs, kRtoMaxMs);

    LINOH_DEBUG("RttEstimator: latest=", latest_rtt_ms,
                " ack_delay=", ack_delay_ms,
                " srtt=", srtt_ms_, " rttvar=", rttvar_ms_,
                " rto=", rto_ms_);
}

void RttEstimator::reset() {
    // P9.1: 跨线程读写保护
    std::lock_guard<std::mutex> lk(rtt_mu_);

    srtt_ms_ = kInitialRttMs;
    rttvar_ms_ = kInitialRttMs / 2.0;
    rto_ms_ = srtt_ms_ + 4 * rttvar_ms_;
    first_sample_ = true;
}

void RttEstimator::on_rto() {
    // P9.1: 跨线程读写保护
    std::lock_guard<std::mutex> lk(rtt_mu_);

    // RFC 6298 §2.5: 触发 RTO 时 back off RTO（×2，封顶 kRtoMaxMs）
    double rto_before = rto_ms_;
    rto_ms_ = std::clamp(rto_ms_ * 2.0, kRtoMinMs, kRtoMaxMs);

    // RFC 9002 §5.5 RTO 雪崩防护：
    //   - srtt 不应超过 RTO（否则 RTO = srtt + 4*rttvar 永远不收敛）
    //   - rttvar 应至少为 srtt/2（保证 RTO 至少有 1 个 SRTT 的安全余量）
    srtt_ms_ = std::min(srtt_ms_, rto_ms_);
    rttvar_ms_ = std::max(rttvar_ms_, srtt_ms_ * 0.5);

    // 埋点诊断 v1.5.0.2.6: RTO 定时器 back off 量化, 对照 rto_before → rto_after.
    LINOH_INFO("RttEstimator: rto_timer FIRED rto_before_ms=", rto_before,
               " rto_after_ms=", rto_ms_,
               " srtt_clamped=", srtt_ms_,
               " rttvar_clamped=", rttvar_ms_);

    LINOH_DEBUG("RttEstimator: on_rto() rto=", rto_ms_,
                " srtt=", srtt_ms_, " rttvar=", rttvar_ms_);
}

// v4.6.0 (借鉴 noq#545): 网络变化重置 RTT 估计器
void RttEstimator::on_network_change() {
    std::lock_guard<std::mutex> lk(rtt_mu_);
    srtt_ms_ = kInitialRttMs;
    rttvar_ms_ = kInitialRttMs / 2.0;
    rto_ms_ = kInitialRttMs;
    first_sample_ = true;
    LINOH_INFO("RttEstimator: on_network_change, reset srtt=", srtt_ms_,
               " rttvar=", rttvar_ms_, " rto=", rto_ms_);
}

// S4（v5.3）: 是否已有真实 RTT 样本（冷启动/网络切换 reset 后为 false）
bool RttEstimator::has_sample() const {
    std::lock_guard<std::mutex> lk(rtt_mu_);
    return !first_sample_;
}

// P9.1: RttEstimator 访问器实现（从 hpp inline 移出，内部加 rtt_mu_ 锁）
double RttEstimator::srtt_ms() const {
    std::lock_guard<std::mutex> lk(rtt_mu_);
    return srtt_ms_;
}

double RttEstimator::rttvar_ms() const {
    std::lock_guard<std::mutex> lk(rtt_mu_);
    return rttvar_ms_;
}

double RttEstimator::rto_ms() const {
    std::lock_guard<std::mutex> lk(rtt_mu_);
    return rto_ms_;
}

// ============================================================================
// LossDetector
// ============================================================================

// v1.5.0.11 (ISSUE T10 反馈): StreamRange 判定边界放宽
//   - 决定：恢复 ±8 字节放宽（kRangeToleranceBytes=8）
//   - 业务证据：T10 实测反查命中率 0.4%（20/4842），严格边界无法覆盖 UDP 抖动导致的
//             STREAM 帧 offset 轻微偏移（< 8 字节）；放宽后命中率理论提升至 ≥ 95%
//   - 兼容方案：v1.5.0.8/v1.5.0.9 旧测试 4 boundary case 改为 ±8 放宽后边界值
//             （offset=payload_bytes+tolerance 仍期望不命中，业务用例不变）
//   - 历史：v1.5.0.10 撤销放宽因破坏旧测试，现 T10 业务证据强于旧测试，调整旧测试
static constexpr int64_t kRangeToleranceBytes = 8;

LossDetector::LossDetector()
    : largest_acked_(0)
    , pto_count_(0)
    , last_ack_time_ms_(0.0) {}

void LossDetector::on_packet_sent(uint64_t pn, double send_time_ms,
                                   uint64_t sent_bytes, bool ack_eliciting,
                                   std::vector<StreamRange> stream_ranges) {
    // P9.1: 全程持 sent_mu_ 锁 — push_back + 冒泡插入与 on_ack_received 的 erase 并发
    std::lock_guard<std::mutex> lk(sent_mu_);

    SentPacketInfo info;
    info.pn = pn;
    info.send_time_ms = send_time_ms;
    info.sent_bytes = sent_bytes;
    info.ack_eliciting = ack_eliciting;
    info.in_flight = true;
    // v1.5.0.9 (ISSUE T08 反馈): 每个 STREAM 帧独立记录 [offset, offset+payload_bytes) 范围
    //   - 解决 v1.5.0.8 单 stream_payload_bytes 字段累加多 stream 字节导致的反查精度错位
    //   - 视频组 T08 实测：offset=651980 处 2024 字节稳定缺口 = A_chunk 1000 + B_chunk 1024 累加
    //   - OOS_PN 反查时遍历 stream_ranges，精确匹配 [range.offset, range.offset+range.payload_bytes) 区间
    //   - 空 vector 表示该 PN 不含 STREAM 帧（控制帧/PING/纯 ACK）
    info.stream_ranges = std::move(stream_ranges);
    // v1.5.0.11 (ISSUE T10 反馈): StreamRange 注册埋点
    //   - 累加本次 on_packet_sent 传入的所有 STREAM frame 范围
    //   - T05 业务 stream_id=1 应持续累加，stream_range_active_size 保持 ≥ 1
    stream_range_add_total_ += info.stream_ranges.size();
    sent_packets_.push_back(info);

    // 保持按 PN 排序以便查找
    // mp-P7 (v1.7.0.8): 乱序时全排序 O(N log N) → 冒泡插入 O(N)
    //   原实现乱序时对整个 vector 做 std::sort，O(N log N) 比较 + 交换。
    //   改为将末尾新元素冒泡到正确位置，最坏 O(N) 次交换，避免全排序。
    //   递增路径（常见）：push_back O(1)，不进入循环，零额外开销。
    if (sent_packets_.size() > 1 &&
        sent_packets_[sent_packets_.size() - 2].pn > pn) {
        auto last = sent_packets_.end() - 1;
        while (last != sent_packets_.begin() && last->pn < (last - 1)->pn) {
            std::iter_swap(last, last - 1);
            --last;
        }
    }
}

/// v1.5.0.5: 测试访问器 — 返回 sent_packets_ 用于 Connection::handle_ack_frame
/// 反查 oos_pn_remote_ 中 offset 对应的 PN。
/// P9.1: 返回 by-value 快照（原返回 const&，悬空风险）；内部加 sent_mu_ 锁
std::vector<SentPacketInfo> LossDetector::sent_packets_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return sent_packets_;  // 拷贝快照
}

// P9.1: find_sent_mut / find_sent_const 为 private，调用方必须持有 sent_mu_ 锁
//   （由 mark_acked/mark_lost/detect_loss_by_* 等持锁方法内部调用），内部不加锁
SentPacketInfo *LossDetector::find_sent_mut(uint64_t pn) {
    for (auto &s : sent_packets_) {
        if (s.pn == pn) return &s;
    }
    return nullptr;
}

const SentPacketInfo *LossDetector::find_sent_const(uint64_t pn) const {
    for (auto &s : sent_packets_) {
        if (s.pn == pn) return &s;
    }
    return nullptr;
}

// P9.1: find_sent 改返回 by-value optional（原返回 const*，锁外失效）；内部加 sent_mu_ 锁
std::optional<SentPacketInfo> LossDetector::find_sent(uint64_t pn) const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    const SentPacketInfo *s = find_sent_const(pn);  // 调用方持锁，内部不加锁
    if (s) return *s;
    return std::nullopt;
}

// P9.1: mark_acked 调用方必须持有 sent_mu_ 锁（on_ack_received / detect_loss_by_pn 等）。
//   内部不加锁，避免重入死锁。测试单线程调用无需加锁。
void LossDetector::mark_acked(uint64_t pn) {
    auto *s = find_sent_mut(pn);
    if (s) {
        // v1.5.0.11 (ISSUE T10 反馈): StreamRange 清理埋点
        //   - 首次 mark_acked（in_flight=true → false）累加 stream_ranges.size()
        //   - 用于派生 stream_range_active_size_ = add - remove
        if (s->in_flight) {
            stream_range_remove_total_ += s->stream_ranges.size();
        }
        s->in_flight = false;
    }
}

// P9.1: mark_lost 调用方必须持有 sent_mu_ 锁。同 mark_acked。
void LossDetector::mark_lost(uint64_t pn) {
    auto *s = find_sent_mut(pn);
    if (s) {
        // v1.5.0.11 (ISSUE T10 反馈): StreamRange 清理埋点（mark_lost 路径）
        if (s->in_flight) {
            stream_range_remove_total_ += s->stream_ranges.size();
        }
        s->in_flight = false;
        LINOH_DEBUG("LossDetector: PN ", pn, " declared lost");
    }
}

// v1.5.0.8 (ISSUE T07 反馈): 接收 Connection::handle_oos_pn_frame 同步的
// OOS buffer PN 列表，立即反查 sent_packets_ 找匹配 PN 并 mark_lost 触发重传。
// v1.5.0.9 (ISSUE T08 反馈): 重构反查逻辑为遍历 stream_ranges 向量，
//   每个 STREAM 帧独立精确匹配 [range.offset, range.offset+range.payload_bytes) 区间，
//   解决 v1.5.0.8 单 stream_payload_bytes 累加导致的多 stream PN 反查精度错位。
std::vector<uint64_t> LossDetector::on_oos_pn_received(
    uint64_t stream_id,
    const std::vector<OosPnEntry> &entries) {

    // P9.1: 全程持 sent_mu_ 锁 — 覆盖 collect（收集 SentPacketInfo* 指针）+ match +
    //   mark_lost 全流程，杜绝 recv_thread 与 send_loop 并发修改 sent_packets_ 导致
    //   指针悬空（原 v1.5.0.9 collect 后遍历期间若 sent_packets_ 被 erase/realloc，
    //   filtered 中的裸指针全部失效 → segfault）
    std::lock_guard<std::mutex> lk(sent_mu_);

    // v1.5.0.8: 入口无条件计数器 +1，便于诊断触发链断裂点
    //   - v1.5.0.7 缺此埋点，video 组无法判断"未调用"还是"调用但反查失败"
    oos_pn_received_total_++;

    std::vector<uint64_t> lost;

    if (entries.empty()) {
        LINOH_DEBUG("LossDetector: on_oos_pn_received stream_id=", stream_id,
                    " entries=0 (empty)");
        return lost;
    }

    // mp-M7 (v1.7.0.8): DoS 防护 — 限制 OOS_PN entries 数量，防止恶意对端
    // 构造超大 OOS_PN_FRAME 触发三重嵌套循环（O(E×N×R)）CPU 占满。
    // 参照 H8 comm_planner 的 kMaxRoutingTokens 模式。
    constexpr std::size_t kMaxOosPnEntries = 65536;
    if (entries.size() > kMaxOosPnEntries) {
        LINOH_WARN("LossDetector: on_oos_pn_received entries too large (",
                   entries.size(), "), dropping to prevent DoS");
        return lost;
    }

    // 反查算法（v1.5.0.9 严格版）：
    //   1. 按 stream_id 过滤 sent_packets_
    //   2. 对每个 entry 在 sent_packets_ 中找 stream_ranges 范围匹配的 PN
    //      - 匹配条件：存在某个 range 满足
    //                  range.stream_id == target_stream_id 且
    //                  range.offset <= entry.offset 且
    //                  range.offset + range.payload_bytes > entry.offset
    //   3. v1.5.0.9 关键修复：遍历 vector<StreamRange> 而非单字段，
    //      解决 v1.5.0.8 多 stream PN 单字段累加错位（视频组 T08 2024 字节稳定缺口）
    //   4. 对 in_flight 的 PN **立即** mark_lost
    //   5. 同一 PN 在多个 entry 中命中时去重
    //
    // 不变量（与 OOS buffer 语义一致）：
    //   - OOS entry 出现时，接收方已收到对端 ACK（recv_offset_ 已推进）
    //   - 所以 entry 对应的 PN 必然 < largest_acked_，否则不应在 OOS buffer
    //   - 但为安全起见，仍仅检查 in_flight 即可保证不会重复 mark_lost
    //
    // mp-P1 (v1.7.0.8): stream_id 预过滤优化。
    //   原实现三重循环 O(E×N×R)：每个 entry 遍历全部 sent_packets_(N)，
    //   每包再遍历 stream_ranges(R) 检查 stream_id 匹配。
    //   优化：先一次性遍历 sent_packets_ 收集包含目标 stream_id 的 packets
    //   到 filtered 子集（O(N×R) 一次），后续每个 entry 只遍历 filtered
    //   （O(E×N_stream×R)），当 N_stream ≪ N 时显著提升。
    //   安全性：sent_packets_ 在本方法中不会被增删（mark_lost 仅修改 in_flight），
    //   指针稳定；语义完全不变（过滤条件与原内层 range.stream_id != stream_id 等价）。
    std::vector<SentPacketInfo*> filtered;
    filtered.reserve(sent_packets_.size());
    for (auto &s : sent_packets_) {
        if (s.stream_ranges.empty()) continue;
        // 检查该 packet 是否包含目标 stream_id 的 range
        for (const auto &range : s.stream_ranges) {
            if (range.stream_id == stream_id) {
                filtered.push_back(&s);
                break;
            }
        }
    }

    std::size_t query_count = 0;
    std::size_t match_count = 0;
    std::size_t in_flight_match = 0;
    for (const auto &entry : entries) {
        ++query_count;
        bool pn_matched = false;
        for (auto *s : filtered) {
            // v1.5.0.9: 跳过非 STREAM 帧的 PN（空 stream_ranges = 控制帧/ACK/PING）
            // mp-P1: filtered 已预过滤，但 packet 可能含多 stream range，仍需逐 range 匹配
            // 遍历所有 STREAM 帧范围，任一匹配即视为该 PN 包含 entry.offset
            bool range_matched = false;
            for (const auto &range : s->stream_ranges) {
                // v1.5.0.11 (ISSUE T10 反馈): StreamRange 判定边界放宽
                //   - kRangeToleranceBytes=8 放宽匹配 [range.offset - 8, range.offset + range.payload_bytes + 8]
                //   - 业务证据：T10 实测 UDP 抖动导致 STREAM 帧 offset 轻微偏移（< 8 字节）
                //   - 判定条件使用 `<` 严格右开：entry.offset > range.offset + payload + tol 才视为越界
                //     - 与 v1.5.0.10 笔误修复兼容：tolerance=0 时等价于严格 [offset, offset+payload)
                //     - tolerance=8 时包含右边界 +8 字节容差
                //   - 仅在反查层放宽，mark_lost 仍走 packet-level 兜底
                if (range.stream_id != stream_id) continue;
                if (range.payload_bytes == 0) continue;
                if (range.offset > entry.offset + kRangeToleranceBytes) continue;
                if (range.offset + range.payload_bytes + kRangeToleranceBytes < entry.offset) continue;
                // 命中：entry.offset 落在 [range.offset - tolerance, range.offset + range.payload_bytes + tolerance] 范围内
                //   v1.5.0.11 放宽边界对应 kRangeToleranceBytes=8：
                //     - range.offset - 8 <= entry.offset （左闭）
                //     - range.offset + range.payload_bytes + 8 >= entry.offset （右闭，包含容差边界）
                range_matched = true;
                break;
            }
            if (!range_matched) {
                // v1.5.0.10: 诊断未命中（每个 PN × 每个 range 累加 1）
                stream_range_unmatched_total_++;
                continue;
            }
            // v1.5.0.10: 诊断命中（每个 PN × 1 个 range 匹配后累加 1）
            stream_range_matched_total_++;
            ++match_count;
            pn_matched = true;
            if (!s->in_flight) {
                // v1.5.0.11 (ISSUE T10 反馈): mark_lost 触发条件审计
                //   - OOS_PN 报告的 PN 已 ACK 或已 mark_lost
                //   - 视频组 T10 实测 20 命中但 0 触发，怀疑此路径占比过大
                //   - 埋点用于诊断：是否需要放宽 in_flight 约束（即便已 ACK 也重传）
                mark_lost_call_total_++;
                mark_lost_skipped_no_inflight_total_++;
                continue;
            }
            ++in_flight_match;
            // v1.5.0.11: mark_lost 真正调用埋点
            mark_lost_call_total_++;
            // 内部去重（同一 PN 在多个 entry 中命中）
            if (std::find(lost.begin(), lost.end(), s->pn) != lost.end()) {
                continue;
            }
            lost.push_back(s->pn);
            mark_lost(s->pn);
            oos_pn_marked_lost_total_++;
            retx_by_oos_pn_total_++;  // v1.5.0.10: 单独量化 OOS_PN 触发的重传
            oos_pn_list_[stream_id].push_back(s->pn);
            LINOH_INFO("LossDetector::on_oos_pn_received: oos_pn_mark_lost ",
                       "stream_id=", stream_id,
                       " pn=", s->pn,
                       " entry_offset=", entry.offset,
                       " first_seen_ms=", entry.first_seen_ms,
                       " stream_ranges_size=", s->stream_ranges.size());
        }
        if (!pn_matched) {
            // 诊断埋点：OOS_PN_FRAME 中的 entry 在 sent_packets_ 没找到匹配 PN
            //   - 可能原因：1) PN 已 evict（kMaxSentPacketsBytes 触发清理）
            //                2) entry.offset 是历史 gap（30s TTL 后已被 OOS buffer 清理）
            //                3) 跨连接注入（不同 connection 的 sent_packets_）
            //   - 不视为错误，仅诊断
            // P-LOG-1: 从 DEBUG 提升为 INFO —— 此埋点被 test_loss_recovery_v1509 断言，
            // 且编译期剥离 Debug 日志后需保留可见性。频率受限于 OOS_PN 帧处理（非每包）。
            LINOH_INFO("LossDetector: on_oos_pn_received no_match ",
                       "stream_id=", stream_id,
                       " entry_offset=", entry.offset,
                       " first_seen_ms=", entry.first_seen_ms);
        }
    }

    LINOH_INFO("LossDetector: on_oos_pn_received summary: ",
               "stream_id=", stream_id,
               " entries=", entries.size(),
               " query_count=", query_count,
               " match_count=", match_count,
               " in_flight_match=", in_flight_match,
               " mark_lost_count=", lost.size(),
               " oos_pn_received_total=", oos_pn_received_total_,
               " oos_pn_marked_lost_total=", oos_pn_marked_lost_total_,
               " stream_range_matched_total=", stream_range_matched_total_,
               " stream_range_unmatched_total=", stream_range_unmatched_total_,
               " retx_by_oos_pn_total=", retx_by_oos_pn_total_);

    return lost;
}

// v1.5.0.8: 测试访问器实现
// P9.1: 内部加 sent_mu_ 锁
std::size_t LossDetector::oos_pn_list_size_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    std::size_t total = 0;
    for (const auto &kv : oos_pn_list_) {
        total += kv.second.size();
    }
    return total;
}

// P9.1: 以下 _for_test 访问器 + largest_acked/pto_count 此前缺失 cpp 定义
//   （上一轮 P9.1 将 inline 改为声明后未补全），导致测试链接失败。统一补充并加 sent_mu_ 锁。

std::size_t LossDetector::oos_pn_received_total_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return oos_pn_received_total_;
}

std::size_t LossDetector::oos_pn_marked_lost_total_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return oos_pn_marked_lost_total_;
}

std::size_t LossDetector::stream_range_matched_total_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return stream_range_matched_total_;
}

std::size_t LossDetector::stream_range_unmatched_total_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return stream_range_unmatched_total_;
}

std::size_t LossDetector::retx_by_oos_pn_total_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return retx_by_oos_pn_total_;
}

std::size_t LossDetector::stream_range_add_total_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return stream_range_add_total_;
}

std::size_t LossDetector::stream_range_remove_total_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return stream_range_remove_total_;
}

std::size_t LossDetector::stream_range_active_size_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    // 派生 gauge = add_total - remove_total（防 size_t 下溢）
    if (stream_range_add_total_ >= stream_range_remove_total_) {
        return stream_range_add_total_ - stream_range_remove_total_;
    }
    return 0;
}

std::size_t LossDetector::stream_range_actual_active_size_for_test() const {
    // 遍历 sent_packets_ 累加每个 PN 的 stream_ranges.size()
    std::lock_guard<std::mutex> lk(sent_mu_);
    std::size_t total = 0;
    for (const auto &s : sent_packets_) {
        total += s.stream_ranges.size();
    }
    return total;
}

std::size_t LossDetector::mark_lost_call_total_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return mark_lost_call_total_;
}

std::size_t LossDetector::mark_lost_skipped_no_inflight_total_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return mark_lost_skipped_no_inflight_total_;
}

std::size_t LossDetector::mark_lost_skipped_out_of_window_total_for_test() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return mark_lost_skipped_out_of_window_total_;
}

uint64_t LossDetector::largest_acked() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return largest_acked_;
}

uint32_t LossDetector::pto_count() const {
    std::lock_guard<std::mutex> lk(sent_mu_);
    return pto_count_;
}

std::vector<uint64_t> LossDetector::on_ack_received(
    const std::vector<uint64_t> &acked_pns,
    double send_time_ms,
    const std::vector<OosPnInfo> &oos_pn_list) {

    // P9.1: 全程持 sent_mu_ 锁 — mark_acked / detect_loss_by_pn / detect_loss_by_time /
    //   detect_early_retransmit / erase / sort 均在锁内。与 send_loop 的 on_packet_sent
    //   push_back 并发时，erase 导致迭代器失效是 segfault 根因，此处串行化修复。
    //   内部调用 mark_acked/mark_lost/detect_*（均不加锁，调用方持锁）；
    //   调用 rtt_.srtt_ms() 会嵌套获取 rtt_mu_（顺序 sent_mu_→rtt_mu_，安全）。
    std::lock_guard<std::mutex> lk(sent_mu_);

    std::vector<uint64_t> lost;

    if (acked_pns.empty()) return lost;

    // 更新 largest_acked
    uint64_t new_largest = acked_pns.back();
    if (new_largest > largest_acked_) {
        largest_acked_ = new_largest;
    }

    // 埋点诊断 v1.5.0.2.6 (2026-07-24): 视频模型组反馈 RTO 触发 + retx 调度路径
    // 完全黑盒 (LINOH_V15025_RECEIVE_FEEDBACK.md §4.2 P1.3). 量化 ACK 入口参数,
    // 对照 largest_acked_ / newly_acked_count / loss_time_filter_ms 的输入输出.
    // v1.5.0.4: 增加 oos_pn_list 统计，关联到 OOS buffer PN 注入路径.
    uint64_t newly_acked_count = acked_pns.size();
    double loss_time_filter_ms = rtt_.srtt_ms() * kTimeThresholdFactor;
    LINOH_INFO("LossDetector::on_ack_received: acked_pns_size=", newly_acked_count,
               " largest_acked_=", largest_acked_,
               " last_ack_time_ms_=", last_ack_time_ms_,
               " send_time_ms=", send_time_ms,
               " loss_time_filter_ms=", loss_time_filter_ms,
               " pto_count_=", pto_count_,
               " oos_pn_list_size=", oos_pn_list.size());

    // 标记所有已确认的包
    for (uint64_t pn : acked_pns) {
        mark_acked(pn);
    }

    // P0-6: 收到 ACK 重置 PTO 退避计数（RFC 9002 §6.2.1）
    pto_count_ = 0;
    last_ack_time_ms_ = send_time_ms;

    // 丢包检测：包编号阈值（含 Fast Retransmit 触发条件）
    // v1.5.0.4: 传入 oos_pn_list，对 OOS buffer 内的 PN 独立应用包编号阈值检测.
    auto pn_lost = detect_loss_by_pn(acked_pns, oos_pn_list);
    lost.insert(lost.end(), pn_lost.begin(), pn_lost.end());
    // 埋点诊断 v1.5.0.2.6: 量化 detect_loss_by_pn 阶段识别出的丢包
    LINOH_INFO("LossDetector: detect_loss_by_pn: pn_lost_count=", pn_lost.size(),
               " threshold=(largest-kPacketThreshold) largest_acked_=", largest_acked_);

    // 丢包检测：时间阈值
    // v1.5.0.4: 传入 oos_pn_list，对 OOS buffer 内的 PN 独立应用时间阈值检测.
    auto time_lost = detect_loss_by_time(acked_pns, send_time_ms, oos_pn_list);
    // mp-P2 (v1.7.0.8): std::find 去重 O(L²) → unordered_set O(L)
    //   lost 已包含 pn_lost 结果，time_lost/early_lost 需去重追加
    std::unordered_set<uint64_t> lost_seen(lost.begin(), lost.end());
    for (uint64_t pn : time_lost) {
        if (lost_seen.insert(pn).second) {
            lost.push_back(pn);
        }
    }
    // 埋点诊断 v1.5.0.2.6: 量化 detect_loss_by_time 阶段识别出的丢包
    LINOH_INFO("LossDetector: detect_loss_by_time: time_lost_count=", time_lost.size(),
               " threshold_ms=", loss_time_filter_ms,
               " now_ms=", send_time_ms);

    // P0-6: Early Retransmit 检测
    auto early_lost = detect_early_retransmit(send_time_ms);
    for (uint64_t pn : early_lost) {
        if (lost_seen.insert(pn).second) {
            lost.push_back(pn);
        }
    }
    // 埋点诊断 v1.5.0.2.6: 量化 Early Retransmit 阶段识别出的丢包
    LINOH_INFO("LossDetector: detect_early_retransmit: early_lost_count=", early_lost.size());

    // 埋点诊断 v1.5.0.2.6: 输出 ACK 阶段总汇总, 对照三阶段共同识别的丢包
    // v1.5.0.4: 增加 oos_pn_list 路径识别出的丢包计数（pn_lost/time_lost 已包含 OOS 阶段结果）.
    LINOH_INFO("LossDetector: on_ack_received summary: acked=", newly_acked_count,
               " lost_total=", lost.size(),
               " lost_by_pn=", pn_lost.size(),
               " lost_by_time=", time_lost.size(),
               " lost_early=", early_lost.size(),
               " oos_pn_list_size=", oos_pn_list.size());

    // 清理已确认和已丢包的记录（保留最近的以做超时检测）
    // v1.5 P2-3: 条目数 + 字节数双重保险
    //   - 保留最近 256 个包记录（条目上限，对齐 RFC 9002 §6.1.4 推荐的 OOO 检测窗口）
    //   - 总字节数上限 128MB（cluster BACKLOG 反馈：长跑推理场景下 sent_packets_
    //     持续膨胀，需要硬上限；128MB ≈ 1M 个 128-byte 包，足够覆盖任何
    //     正常 PTO/RTO 重传窗口）。超出时按 PN 升序驱逐非飞行中包。
    constexpr uint64_t kMaxSentPacketsBytes = 128ULL * 1024 * 1024;
    if (sent_packets_.size() > 256) {
        uint64_t keep_threshold = (largest_acked_ > 256) ? largest_acked_ - 256 : 0;
        sent_packets_.erase(
            std::remove_if(sent_packets_.begin(), sent_packets_.end(),
                [&](const SentPacketInfo &s) {
                    return !s.in_flight && s.pn < keep_threshold;
                }),
            sent_packets_.end());
    }
    if (sent_packets_.size() > 256) {
        // v1.5 P2-3: 字节数上限
        uint64_t total = 0;
        for (auto &s : sent_packets_) total += s.sent_bytes;
        if (total > kMaxSentPacketsBytes) {
            // 按 PN 升序驱逐最旧非飞行中包直到降到上限
            std::sort(sent_packets_.begin(), sent_packets_.end(),
                [](const SentPacketInfo &a, const SentPacketInfo &b) {
                    return a.pn < b.pn;
                });
            LINOH_WARN("LossDetector: sent_packets_ total=", total,
                       " bytes exceeds limit=", kMaxSentPacketsBytes,
                       ", evicting oldest non-in-flight");
            sent_packets_.erase(
                std::remove_if(sent_packets_.begin(), sent_packets_.end(),
                    [&](const SentPacketInfo &s) {
                        // 仍保留 256 个最新包以支持 PTO/RTO 重传决策
                        if (s.in_flight) return false;
                        if (total <= kMaxSentPacketsBytes) return false;
                        total -= s.sent_bytes;
                        return true;
                    }),
                sent_packets_.end());
        }
    }

    // v1.7.0.7 H7: 绝对条目数硬上限 — 防止全 in-flight 场景下 sent_packets_ 无限增长
    //   根因：前两段驱逐条件均使用 !s.in_flight，当网络长时间 stalled（对端无响应
    //   但未 RTO）时，所有 256+ 包都 in_flight=true，驱逐永不命中，sent_packets_
    //   持续增长。长跑推理场景下（每秒数百包）数小时可累积数百万条目。
    //   修复：增加绝对硬上限 10000 条，超过时按 PN 升序强制驱逐最旧条目
    //   （含 in_flight），in_flight 的标记 lost 但不加入返回列表（这些包太旧，
    //   重传已无意义，RTO 机制会独立处理对端不响应场景）。
    constexpr size_t kMaxSentPacketsAbsolute = 10000;
    if (sent_packets_.size() > kMaxSentPacketsAbsolute) {
        size_t to_evict = sent_packets_.size() - kMaxSentPacketsAbsolute;
        std::sort(sent_packets_.begin(), sent_packets_.end(),
            [](const SentPacketInfo &a, const SentPacketInfo &b) {
                return a.pn < b.pn;
            });
        LINOH_WARN("LossDetector: sent_packets_ size=", sent_packets_.size(),
                   " exceeds absolute limit=", kMaxSentPacketsAbsolute,
                   ", force-evicting ", to_evict, " oldest (incl in-flight)");
        // 驱逐最旧的 to_evict 个条目，in_flight 的标记 lost（清理 stream_ranges 埋点）
        for (size_t i = 0; i < to_evict; ++i) {
            if (sent_packets_[i].in_flight) {
                sent_packets_[i].in_flight = false;
                stream_range_remove_total_ += sent_packets_[i].stream_ranges.size();
            }
        }
        sent_packets_.erase(sent_packets_.begin(),
                            sent_packets_.begin() + to_evict);
    }

    return lost;
}

std::vector<uint64_t> LossDetector::detect_loss_by_pn(
    const std::vector<uint64_t> &acked_pns,
    const std::vector<OosPnInfo> &oos_pn_list) {

    std::vector<uint64_t> lost;
    if (acked_pns.empty()) return lost;

    uint64_t largest = acked_pns.back();
    // 埋点诊断 v1.5.0.2.5 (2026-07-23): 视频模型组反馈 STREAM buffer 累积,
    // 怀疑 acked_pns 乱序导致 largest 取值偏小, 进而 threshold 偏低,
    // 飞行中包被误判丢包触发重传风暴. 对照 acked_pns.back() / actual_largest / largest_acked_.
    uint64_t actual_largest = *std::max_element(acked_pns.begin(), acked_pns.end());
    LINOH_DEBUG("LossDetector: detect_loss_by_pn acked.back()=", largest,
                " actual_largest=", actual_largest,
                " largest_acked_=", largest_acked_,
                " acked_count=", acked_pns.size());

    // 任何 PN < largest - kPacketThreshold 的飞行中包视为丢包
    uint64_t threshold = (largest > static_cast<uint64_t>(kPacketThreshold))
        ? largest - static_cast<uint64_t>(kPacketThreshold)
        : 0;

    // === 阶段 1: sent_packets_ 队列（保持原逻辑）===
    for (auto &s : sent_packets_) {
        if (s.in_flight && s.pn < threshold) {
            lost.push_back(s.pn);
            mark_lost(s.pn);
        }
    }

    // === v1.5.0.4 阶段 2: OOS buffer PN 列表（方案 A 关键修复）===
    // 根因 (LINOH_V1504_LOSSDETECTOR_DESIGN.md §3 P0-2)：
    //   当 PN 处于 OOS buffer 等待 gap 填补时，对端可能已 ACK 确认该 PN
    //   （标记为已确认但 STREAM 数据仍未按序到达）。sent_packets_ 中该 PN
    //   的 in_flight=false，导致阶段 1 循环无法匹配，永久不触发 retx。
    //   方案 A：将 OOS buffer 内每个 entry 的 PN 注入本检测函数，独立
    //   应用包编号阈值，触发缺失的 retx 调度。
    //
    // 安全护栏 (Q2 答复)：
    //   - 同一 PN 可能在 sent_packets_ 和 oos_pn_list 同时出现，需在阶段 2
    //     内部去重（与 on_ack_received 后续 time_lost/early_lost 去重一致）。
    //   - OOS PN 必定 < largest（因为 OOS entry 的 offset > recv_offset_，
    //     而 largest >= sent_packets_.back()），threshold 过滤天然避免误判
    std::size_t oos_pn_mark_lost = 0;
    // mp-P2 (v1.7.0.8): std::find 去重 O(L²) → unordered_set O(L)
    std::unordered_set<uint64_t> pn_seen(lost.begin(), lost.end());
    for (const auto &o : oos_pn_list) {
        if (o.pn < threshold) {
            // 去重（避免与阶段 1 sent_packets_ 已识别的 PN 重复）
            if (pn_seen.insert(o.pn).second) {
                lost.push_back(o.pn);
                ++oos_pn_mark_lost;
                // 关键埋点：记录"OOS buffer PN 通过包编号阈值检测触发 retx"
                LINOH_INFO("LossDetector::detect_loss_by_pn: oos_pn_mark_lost ",
                           "stream_id=", o.stream_id,
                           " pn=", o.pn,
                           " offset=", o.offset,
                           " size=", o.size,
                           " first_seen_ms=", o.first_seen_ms);
            }
        }
    }

    // v1.5.0.3.1 P0-3 fix: in_flight 诊断埋点（量化实际飞行中包状态）
    // 根因（LINOH_V1503_T05_FEEDBACK）: retx_queue_size=0, 怀疑 in_flight 已 mark_acked
    // 或 pn > largest 导致循环不触发。统计飞行中包总数和低于 threshold 的数量。
    // v1.5.0.4: 增加 oos_pn 统计字段，关联到阶段 2 OOS 路径.
    std::size_t in_flight_total = 0;
    std::size_t in_flight_below_threshold = 0;
    for (const auto &s : sent_packets_) {
        if (s.in_flight) {
            ++in_flight_total;
            if (s.pn < threshold) ++in_flight_below_threshold;
        }
    }
    std::size_t oos_pn_total = oos_pn_list.size();
    std::size_t oos_pn_below_threshold = 0;
    for (const auto &o : oos_pn_list) {
        if (o.pn < threshold) ++oos_pn_below_threshold;
    }

    LINOH_INFO("LossDetector::detect_loss_by_pn: largest=", largest,
               " actual_largest=", actual_largest,
               " threshold=", threshold,
               " in_flight_total=", in_flight_total,
               " in_flight_below_threshold=", in_flight_below_threshold,
               " oos_pn_total=", oos_pn_total,
               " oos_pn_below_threshold=", oos_pn_below_threshold,
               " oos_pn_mark_lost=", oos_pn_mark_lost,
               " acked_pns_size=", acked_pns.size(),
               " sent_packets_size=", sent_packets_.size(),
               " lost_size=", lost.size());

    return lost;
}

std::vector<uint64_t> LossDetector::detect_loss_by_time(
    const std::vector<uint64_t> &acked_pns,
    double now_ms,
    const std::vector<OosPnInfo> &oos_pn_list) {

    std::vector<uint64_t> lost;
    if (acked_pns.empty()) return lost;

    // S4（v5.3）冷启动豁免窗：尚无真实 RTT 样本时（冷启动/网络切换 reset 后，
    // srtt 是 kInitialRttMs=100ms 假设值）跳过时间阈值检测——高 RTT 链路上
    // 首个包会在首个 ACK 到达前被误判丢失（心跳流冷启动单包误判 ~1 次/s 根因）。
    // 真实丢包仍由 PN 阈值检测覆盖（不依赖 RTT）；首个 ACK 携带样本后本检测恢复。
    if (!rtt_.has_sample()) {
        LINOH_DEBUG("LossDetector::detect_loss_by_time: cold-start exemption "
                    "(no RTT sample yet), skip time-threshold detection");
        return lost;
    }

    // 时间阈值: loss_time = largest_acked.send_time + kTimeThreshold * SRTT
    double loss_threshold_ms = rtt_.srtt_ms() * kTimeThresholdFactor;

    // v1.5.0.3.1 P0-3 fix: 输入参数诊断埋点（量化飞行中包状态）
    // v1.5.0.4: 增加 oos_pn_list 相关统计字段.
    std::size_t in_flight_total = 0;
    std::size_t in_flight_below_largest = 0;
    for (const auto &s : sent_packets_) {
        if (s.in_flight) {
            ++in_flight_total;
            if (s.pn < largest_acked_) ++in_flight_below_largest;
        }
    }
    LINOH_INFO("LossDetector::detect_loss_by_time: largest_acked=", largest_acked_,
               " srtt_ms=", rtt_.srtt_ms(),
               " loss_threshold_ms=", loss_threshold_ms,
               " in_flight_total=", in_flight_total,
               " in_flight_below_largest=", in_flight_below_largest,
               " oos_pn_list_size=", oos_pn_list.size(),
               " acked_pns_size=", acked_pns.size(),
               " now_ms=", now_ms);

    // === 阶段 1: sent_packets_ 队列（保持原逻辑）===
    for (auto &s : sent_packets_) {
        if (s.in_flight && s.pn < largest_acked_) {
            double elapsed = now_ms - s.send_time_ms;
            if (elapsed > loss_threshold_ms) {
                lost.push_back(s.pn);
                mark_lost(s.pn);
                // 埋点诊断 v1.5.0.2.6: 时间阈值丢包逐个标记,
                // 量化 RTO 多久检测到丢包 → 对照 elapsed / threshold.
                LINOH_INFO("LossDetector: time_lost_packet pn=", s.pn,
                           " sent_time_ms=", s.send_time_ms,
                           " elapsed_ms=", elapsed,
                           " threshold_ms=", loss_threshold_ms);
            }
        }
    }

    // === v1.5.0.4 阶段 2: OOS buffer PN 时间阈值检测（Q1 答复：entry 级别精度）===
    // 当 OOS entry 在 buffer 中 wait 时间超过 kTimeThreshold * SRTT，触发 retx。
    // 关键差异：本路径使用 oos_first_seen_ms_（entry 首次插入时间），而非
    // sent_packets_ 的 send_time_ms（包发送时间），因为 OOS 数据到达接收侧
    // 时间和发送时间存在网络延迟差距。
    //
    // 触发条件：
    //   1. oos_first_seen_ms > 0（已初始化）
    //   2. now_ms - oos_first_seen_ms > loss_threshold_ms（OOS wait 超时）
    //
    // 不变量：OOS entry 的 PN 必然 < largest_acked_（OOS 数据到达时
    // recv_offset_ 已推进，对端已 ACK 确认），与 RFC 9002 §6.1 一致。
    std::size_t oos_time_mark_lost = 0;
    // mp-P2 (v1.7.0.8): std::find 去重 O(L²) → unordered_set O(L)
    std::unordered_set<uint64_t> time_seen(lost.begin(), lost.end());
    for (const auto &o : oos_pn_list) {
        if (o.first_seen_ms <= 0.0) continue;  // 未初始化
        double oos_wait_ms = now_ms - o.first_seen_ms;
        if (oos_wait_ms > loss_threshold_ms) {
            // 去重（避免与 detect_loss_by_pn 阶段 2 或 sent_packets_ 阶段 1 重复）
            if (time_seen.insert(o.pn).second) {
                lost.push_back(o.pn);
                ++oos_time_mark_lost;
                // 关键埋点：记录"OOS buffer PN 通过时间阈值检测触发 retx"
                LINOH_INFO("LossDetector::detect_loss_by_time: oos_pn_time_lost ",
                           "stream_id=", o.stream_id,
                           " pn=", o.pn,
                           " oos_wait_ms=", oos_wait_ms,
                           " threshold_ms=", loss_threshold_ms,
                           " offset=", o.offset,
                           " size=", o.size);
            }
        }
    }
    if (oos_time_mark_lost > 0) {
        LINOH_INFO("LossDetector::detect_loss_by_time: oos_time_mark_lost_count=", oos_time_mark_lost,
                   " oos_pn_list_size=", oos_pn_list.size());
    }

    return lost;
}

std::vector<uint64_t> LossDetector::on_rto_timeout(double send_time_ms) {
    // P9.1: 全程持 sent_mu_ 锁 — 遍历 sent_packets_ + mark_lost 与 on_packet_sent/
    //   on_ack_received 并发。不调用 in_flight_count()（内部也取 sent_mu_，重入死锁），
    //   改为持锁状态下直接遍历计数。rtt_.on_rto()/rto_ms() 等内部取 rtt_mu_，
    //   锁序 sent_mu_→rtt_mu_ 固定，安全。
    std::lock_guard<std::mutex> lk(sent_mu_);
    std::vector<uint64_t> lost;

    // P9.1: 直接遍历计数，避免调用 in_flight_count() 重入死锁
    uint64_t in_flight = 0;
    for (const auto &s : sent_packets_) {
        if (s.in_flight) ++in_flight;
    }

    // 埋点诊断 v1.5.0.2.6: RTO 触发时刻量化,
    // 对照 now_ms / rto_ms_ / sent_packets_ 飞行中数量.
    LINOH_INFO("LossDetector: RTO FIRED now_ms=", send_time_ms,
               " rto_ms_=", rtt_.rto_ms(),
               " srtt_ms_=", rtt_.srtt_ms(),
               " rttvar_ms_=", rtt_.rttvar_ms(),
               " in_flight_count=", in_flight,
               " pto_count_=", pto_count_);

    // RTO 超时：所有飞行中的包视为丢包
    for (auto &s : sent_packets_) {
        if (s.in_flight) {
            lost.push_back(s.pn);
            mark_lost(s.pn);
            // 埋点诊断 v1.5.0.2.6: RTO 强制丢包逐个标记, 量化 RTO → 丢包链路.
            LINOH_INFO("LossDetector: rto_lost_packet pn=", s.pn,
                       " sent_time_ms=", s.send_time_ms,
                       " elapsed_ms=", send_time_ms - s.send_time_ms);
        }
    }

    LINOH_WARN("LossDetector: RTO timeout, ", lost.size(), " packets declared lost");

    // v1.5 P2-1: RTO 触发后 back off RTO + srtt clamp（防雪崩）
    rtt_.on_rto();

    return lost;
}

// ============================================================================
// P0-6: PTO (Probe Timeout) — RFC 9002 §6.2.1
// ============================================================================

std::vector<uint64_t> LossDetector::on_pto_timeout(double now_ms) {
    // PTO 触发：发送 1-2 个探测包（重传最早的 ack-eliciting 飞行中包）
    // PTO 不会声明丢包，只是激发对端 ACK

    // P9.1: 全程持 sent_mu_ 锁 — 遍历 sent_packets_ 收集指针 + sort + 使用全程在锁内，
    //   持锁期间无并发修改（on_packet_sent/on_ack_received 阻塞等待锁），指针不悬空
    std::lock_guard<std::mutex> lk(sent_mu_);
    std::vector<uint64_t> probes;

    // 收集所有 ack-eliciting 的飞行中包，按 PN 排序
    std::vector<const SentPacketInfo *> ack_eliciting_in_flight;
    for (auto &s : sent_packets_) {
        if (s.in_flight && s.ack_eliciting) {
            ack_eliciting_in_flight.push_back(&s);
        }
    }

    if (ack_eliciting_in_flight.empty()) {
        // v4.6.0 (借鉴 noq#561): TLP 必须 ack-eliciting — 无 ack-eliciting in-flight
        // 时强制要求上层发 PING 帧（ack-eliciting），避免"看似存活实则停滞"
        // 旧版返回空 vector 由上层决定，但上层 PING 请求路径可能被 PTO 退避延迟
        // 新版返回 {kForcePingPn} 显式标记，上层 loss_tick_loop 立即发 PING
        LINOH_INFO("LossDetector: PTO fired but no ack-eliciting in-flight, "
                   "FORCE send PING (noq#561)");
        if (pto_count_ < kMaxPtoCount) {
            ++pto_count_;
        }
        probes.push_back(kForcePingPn);  // 强制 PING 标记
        return probes;
    }

    // 按 PN 排序，取最早的 1-2 个作为探测重传
    std::sort(ack_eliciting_in_flight.begin(), ack_eliciting_in_flight.end(),
              [](const SentPacketInfo *a, const SentPacketInfo *b) {
                  return a->pn < b->pn;
              });

    probes.push_back(ack_eliciting_in_flight[0]->pn);
    if (ack_eliciting_in_flight.size() > 1) {
        probes.push_back(ack_eliciting_in_flight[1]->pn);
    }

    // 递增 pto_count（指数退避）
    if (pto_count_ < kMaxPtoCount) {
        ++pto_count_;
    }

    LINOH_INFO("LossDetector: PTO fired, pto_count=", pto_count_,
               " probes=", probes.size(), " now=", now_ms);
    return probes;
}

double LossDetector::pto_timeout_ms(double now_ms) const {
    // RFC 9002 §6.2.1: PTO = max(SRTT + 4*RTTVAR, kGranularity) * 2^pto_count
    // 但要确保有 ack-eliciting 的飞行中包

    // P9.1: 全程持 sent_mu_ 锁 — 遍历 sent_packets_ + 读 pto_count_；
    //   rtt_.srtt_ms()/rttvar_ms() 内部取 rtt_mu_，锁序 sent_mu_→rtt_mu_ 安全
    std::lock_guard<std::mutex> lk(sent_mu_);

    // 查找最早的 ack-eliciting 飞行中包的发送时间
    double earliest_send = 0;
    bool has_ack_eliciting = false;
    for (auto &s : sent_packets_) {
        if (s.in_flight && s.ack_eliciting) {
            if (!has_ack_eliciting || s.send_time_ms < earliest_send) {
                earliest_send = s.send_time_ms;
                has_ack_eliciting = true;
            }
        }
    }

    if (!has_ack_eliciting) return -1.0;  // 无需 PTO

    // 计算 PTO duration
    double pto_duration = std::max(
        rtt_.srtt_ms() + 4.0 * rtt_.rttvar_ms(),
        kGranularityMs);

    // 指数退避: * 2^pto_count
    double backoff = 1.0;
    for (uint32_t i = 0; i < pto_count_ && i < kMaxPtoCount; ++i) {
        backoff *= kPtoBackoffFactor;
    }
    pto_duration *= backoff;

    // v4.6.0 (借鉴 noq#523): PTO 上限 clamp — 防止持续丢包下 PTO 指数退避
    // 到数十秒导致连接假死。握手后上限 2s，握手期上限 500ms。
    // SRTT=50ms 时原退避可达 50ms * 2^16 ≈ 3276s，clamp 后 ≤ 2s
    double pto_cap = is_handshake_complete_ ? kPtoMaxPostHandshakeMs : kPtoMaxHandshakeMs;
    if (pto_duration > pto_cap) {
        LINOH_DEBUG("LossDetector: PTO clamp ", pto_duration, "ms -> ", pto_cap,
                    "ms (handshake_complete=", is_handshake_complete_,
                    ", pto_count=", pto_count_, ")");
        pto_duration = pto_cap;
    }

    // PTO 超时时间 = earliest_send + pto_duration
    double pto_time = earliest_send + pto_duration;
    double remaining = pto_time - now_ms;
    return remaining > 0 ? remaining : 0.0;
}

// v4.6.0 (借鉴 noq#545): 网络变化通知 — 重置 PTO backoff
// 网络切换（如 WiFi↔Cellular、IP 变化）后，旧 PTO 退避计数不再适用，
// 重置为 0 让下一次 PTO 用基础超时（无退避），加快恢复。
// 同时联动 RttEstimator::on_network_change 重置 RTT 估计。
void LossDetector::on_network_change() {
    std::lock_guard<std::mutex> lk(sent_mu_);
    uint32_t old_count = pto_count_;
    pto_count_ = 0;  // 重置 PTO 退避
    LINOH_INFO("LossDetector: on_network_change, pto_count reset ",
               old_count, " -> 0");
    // 联动 RTT 估计器重置（rtt_ 内部 rtt_mu_ 锁，锁序 sent_mu_ -> rtt_mu_ 安全）
    rtt_.on_network_change();
}

std::vector<uint64_t> LossDetector::detect_early_retransmit(double now_ms) {
    // RFC 9002 §6.1.2: Early Retransmit
    // 当飞行中 ack-eliciting 包数量 < kPacketThreshold 时，
    // 在 loss_delay = max(SRTT/8, 1ms) * kTimeThresholdFactor 后触发丢包检测
    //
    // 触发条件：
    //   1. 无新丢包检测（pn_threshold 和 time_threshold 都未触发）
    //   2. 飞行中 ack-eliciting 包数量 < kPacketThreshold
    //   3. 距上次 ACK 已超过 early_retransmit_delay

    std::vector<uint64_t> lost;

    // 统计飞行中 ack-eliciting 包数量
    uint64_t ack_eliciting_count = 0;
    for (auto &s : sent_packets_) {
        if (s.in_flight && s.ack_eliciting) {
            ++ack_eliciting_count;
        }
    }

    // 仅在飞行中包数 < kPacketThreshold 时启用 Early Retransmit
    if (ack_eliciting_count >= static_cast<uint64_t>(kPacketThreshold)) {
        return lost;
    }
    if (ack_eliciting_count == 0) {
        return lost;
    }

    // Early Retransmit 延迟 = SRTT * kTimeThresholdFactor（但至少 1ms）
    double early_delay = std::max(rtt_.srtt_ms() * kTimeThresholdFactor, 1.0);

    // 距上次 ACK 的时间
    double elapsed = now_ms - last_ack_time_ms_;
    if (elapsed < early_delay) {
        return lost;
    }

    // 触发 Early Retransmit：将所有 PN < largest_acked_ 的飞行中包标记为丢包
    for (auto &s : sent_packets_) {
        if (s.in_flight && s.pn < largest_acked_) {
            lost.push_back(s.pn);
            mark_lost(s.pn);
        }
    }

    // mp-L6 (v1.7.0.8): 返回前按 PN 升序排序。
    //   sent_packets_ 遍历顺序不保证 PN 升序（并发重传/乱序插入），
    //   调用方（如 connection.cpp handle_loss）期望 lost 按 PN 升序处理
    //   （如批量 retx 时按序号顺序发送，避免对端 OOS_PN 反向触发）。
    std::sort(lost.begin(), lost.end());

    if (!lost.empty()) {
        LINOH_INFO("LossDetector: Early Retransmit triggered, ",
                   lost.size(), " packets declared lost, elapsed=", elapsed,
                   "ms, early_delay=", early_delay, "ms");
    }

    return lost;
}

double LossDetector::next_timeout_ms(double now_ms) const {
    // P9.1: 全程持 sent_mu_ 锁 — 遍历 sent_packets_ + 读 pto_count_；
    //   rtt_.rto_ms()/srtt_ms()/rttvar_ms() 内部取 rtt_mu_，锁序 sent_mu_→rtt_mu_ 安全
    std::lock_guard<std::mutex> lk(sent_mu_);

    // 最早飞行中包的超时时间
    double earliest_send = 0;
    bool has_in_flight = false;
    for (auto &s : sent_packets_) {
        if (s.in_flight) {
            if (!has_in_flight || s.send_time_ms < earliest_send) {
                earliest_send = s.send_time_ms;
                has_in_flight = true;
            }
        }
    }

    if (!has_in_flight) return -1.0; // 无超时

    // RTO 超时 = earliest_send + RTO
    double rto_time = earliest_send + rtt_.rto_ms();

    // 时间阈值丢包超时 = earliest_send + kTimeThreshold * SRTT
    double loss_time = earliest_send + rtt_.srtt_ms() * kTimeThresholdFactor;

    // P0-6: PTO 超时（如果有 ack-eliciting 包）
    // v4.6.0 (借鉴 noq#523): 同步加 PTO 上限 clamp，与 pto_timeout_ms() 保持一致
    double pto_time = std::numeric_limits<double>::max();
    double pto_cap = is_handshake_complete_ ? kPtoMaxPostHandshakeMs : kPtoMaxHandshakeMs;
    for (auto &s : sent_packets_) {
        if (s.in_flight && s.ack_eliciting) {
            double pto_duration = std::max(
                rtt_.srtt_ms() + 4.0 * rtt_.rttvar_ms(),
                kGranularityMs);
            double backoff = 1.0;
            for (uint32_t i = 0; i < pto_count_ && i < kMaxPtoCount; ++i) {
                backoff *= kPtoBackoffFactor;
            }
            pto_duration *= backoff;
            // v4.6.0: PTO 上限 clamp（与 pto_timeout_ms 一致）
            if (pto_duration > pto_cap) {
                pto_duration = pto_cap;
            }
            double this_pto = s.send_time_ms + pto_duration;
            if (this_pto < pto_time) pto_time = this_pto;
            break;  // 只看最早的
        }
    }

    // 取最早的超时
    double timeout = std::min({rto_time, loss_time, pto_time});

    // 返回距离超时的剩余时间
    double remaining = timeout - now_ms;
    return remaining > 0 ? remaining : 0;
}

uint64_t LossDetector::in_flight_count() const {
    // P9.1: 加 sent_mu_ 锁 — 遍历 sent_packets_ 与 on_packet_sent/on_ack_received 并发
    std::lock_guard<std::mutex> lk(sent_mu_);
    uint64_t count = 0;
    for (auto &s : sent_packets_) {
        if (s.in_flight) count++;
    }
    return count;
}

uint64_t LossDetector::in_flight_bytes() const {
    // P9.1: 加 sent_mu_ 锁 — 同 in_flight_count
    std::lock_guard<std::mutex> lk(sent_mu_);
    uint64_t bytes = 0;
    for (auto &s : sent_packets_) {
        if (s.in_flight) bytes += s.sent_bytes;
    }
    return bytes;
}

// ============================================================================
// NewRenoController
// ============================================================================

// P9.2: steady_clock 当前时间（毫秒），用于 cwnd 抑制态超时判断
double NewRenoController::now_ms_steady() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(now.time_since_epoch()).count();
}

NewRenoController::NewRenoController()
    // v1.5.0.1 P2-2: 严格 RFC 6928 IW10（10 * MSS = 10 * 1460 = 14600 字节）。
    // 之前用 kInitialCwnd * 1200 = 12000 字节（QUIC 默认 MTU），不符合 RFC 6928
    // 推荐值。RFC 6928 §3: IW = min(10*MSS, max(2*MSS, 14600)) = 14600 (Ethernet MSS=1460)。
    : cwnd_bytes_(kInitialCwndBytes)        // RFC 6928 IW10 = 14600 bytes
    , ssthresh_(UINT64_MAX)                 // 初始 ssthresh 无上限
    , in_recovery_(false)
    , recovery_start_pn_(0) {}

void NewRenoController::on_ack(uint64_t newly_acked_bytes, uint64_t largest_acked_pn) {
    // P9.1: 全程持 mu_ 锁 — cwnd/ssthresh/in_recovery 被 recv_thread(on_ack/on_loss) 与
    //   send_loop(can_send/cwnd_bytes) 并发读写。不调用 is_cwnd_suppressed()（内部也取
    //   mu_，重入死锁），改为持锁状态下直接判断 retx_pending_count_ > kCwndSuppressThreshold。
    std::lock_guard<std::mutex> lk(mu_);

    // P9.2 层 1+2: cwnd 抑制 — 带超时退出 + 抑制态微量增长
    //   死锁链（P9 方案 §P9.2）：retx backlog > 100 → is_cwnd_suppressed=true →
    //     on_ack 早 return（cwnd 永不增长）→ in-flight 无法 ACK → retx 永不成功 →
    //     抑制态自维持 → LLMPP flush 60s busy-wait
    //   修复：
    //   层 1 — 抑制态超过 kSuppressMaxMs(5s) 强制退出，恢复 cwnd 正常增长
    //   层 2 — 抑制态内仍以 1/4 速率增长 cwnd，避免完全饿死，让新数据推进
    //          间接排空 retx 队列
    bool is_suppressed = (retx_pending_count_ > kCwndSuppressThreshold);
    bool suppress_timed_out = false;
    if (is_suppressed && suppressed_since_ms_ > 0.0) {
        double now = now_ms_steady();
        if (now - suppressed_since_ms_ > kSuppressMaxMs) {
            suppress_timed_out = true;
        }
    }

    if (is_suppressed && !suppress_timed_out) {
        // P9.2 层 2: 抑制态微量增长（1/4 速率），避免完全饿死
        //   原 v1.5.0.9 直接 return 导致 cwnd 冻结，新数据无法推进
        //   1/4 速率 = cwnd += newly_acked_bytes / 4，约为正常增长的 25%
        cwnd_bytes_ += newly_acked_bytes / 4;
        double suppressed_dur = (suppressed_since_ms_ > 0.0)
                                ? (now_ms_steady() - suppressed_since_ms_) : 0.0;
        LINOH_INFO("NewReno::on_ack: cwnd_suppressed micro_grow retx_pending=",
                   retx_pending_count_,
                   " threshold=", kCwndSuppressThreshold,
                   " cwnd=", cwnd_bytes_,
                   " newly_acked=", newly_acked_bytes,
                   " suppressed_dur_ms=", suppressed_dur);
        return;
    }

    if (suppress_timed_out) {
        // P9.2 层 1: 抑制超时，强制退出抑制态，恢复正常 cwnd 增长
        double suppressed_dur = now_ms_steady() - suppressed_since_ms_;
        LINOH_WARN("NewReno::on_ack: cwnd_suppress TIMEOUT EXIT after ", suppressed_dur,
                   "ms (max=", kSuppressMaxMs, "), forcing cwnd growth, retx_pending=",
                   retx_pending_count_);
        // 清除抑制态标记，后续 on_ack 不再被抑制
        suppressed_since_ms_ = 0.0;
    }

    if (in_recovery_) {
        // v1.7.0.7 H5/H6: RFC 9002 §7.3.2 recovery 退出条件
        // largest_acked_pn 非哨兵且超过 recovery_start_pn_ 时退出 recovery
        // （说明 recovery 前的包已全部被确认）
        if (largest_acked_pn != UINT64_MAX && largest_acked_pn > recovery_start_pn_) {
            in_recovery_ = false;
            LINOH_INFO("NewReno::on_ack: recovery exited, largest_acked_pn=",
                       largest_acked_pn, " recovery_start_pn=", recovery_start_pn_);
        } else {
            // 快速恢复：每个 ACK 增加 cwnd by newly_acked_bytes (抵消重传消耗)
            // NewReno: cwnd += SMSS * newly_acked_bytes / cwnd
            cwnd_bytes_ += newly_acked_bytes;
        }
    } else if (cwnd_bytes_ < ssthresh_) {
        // 慢启动：每个 ACK 窗口翻倍
        cwnd_bytes_ += newly_acked_bytes;
    } else {
        // 拥塞避免：每个 ACK 增加 1 MSS / cwnd
        // 简化为：cwnd += (MSS * newly_acked_bytes) / cwnd
        uint64_t mss = kMssBytes;  // v1.5.0.1 P2-2: 严格 RFC 6928 MSS=1460
        cwnd_bytes_ += (mss * newly_acked_bytes) / cwnd_bytes_;
    }

    LINOH_DEBUG("NewReno: on_ack, newly_acked=", newly_acked_bytes,
                " cwnd=", cwnd_bytes_, " ssthresh=", ssthresh_,
                " recovery=", in_recovery_);
    // 埋点诊断 v1.5.0.2.6: cwnd 慢启动/拥塞避免/恢复变化量化,
    // 对照 cwnd / ssthresh 判断 cwnd 限流是否丢首包.
    // v1.5.0.2.7: ssthresh_=UINT64_MAX 时输出 "INF" (RFC 9002 §7.3.1 标准),
    // 避免日志显示 18446744073709551615 难以理解. 测试 marker "ssthresh=" 仍命中.
    if (ssthresh_ == UINT64_MAX) {
        LINOH_INFO("NewReno::on_ack: cwnd_bytes=", cwnd_bytes_,
                   " ssthresh=INF",
                   " newly_acked=", newly_acked_bytes,
                   " recovery=", in_recovery_);
    } else {
        LINOH_INFO("NewReno::on_ack: cwnd_bytes=", cwnd_bytes_,
                   " ssthresh=", ssthresh_,
                   " newly_acked=", newly_acked_bytes,
                   " recovery=", in_recovery_);
    }
}

void NewRenoController::on_loss(uint64_t current_largest_acked) {
    // P9.1: 全程持 mu_ 锁 — 修改 cwnd/ssthresh/in_recovery/recovery_start_pn
    std::lock_guard<std::mutex> lk(mu_);

    // P9.3 §4.3: on_loss 去抖 — 同一 recovery 窗口内不反复减半 ssthresh
    //   RFC 9002 §7.3.2: "A sender in recovery SHOULD NOT reduce ssthresh again
    //   until the recovery period ends." 原 v1.7.0.7 每次 on_loss 都减半，
    //   导致 5% 丢包下 ssthresh 反复减半 → cwnd 在 14600↔239824 间振荡。
    //   修复：in_recovery_=true 且 current_largest_acked <= recovery_start_pn_
    //   时跳过（说明仍在同一 recovery 窗口内）。
    if (in_recovery_ && current_largest_acked != 0 &&
        current_largest_acked <= recovery_start_pn_) {
        LINOH_INFO("NewReno::on_loss: DEBOUNCE skip (in_recovery, current_largest=",
                   current_largest_acked, " <= recovery_start=", recovery_start_pn_,
                   "), cwnd=", cwnd_bytes_, " ssthresh=", ssthresh_);
        return;
    }

    // P9.3 §4.3: ssthresh EWMA 平滑 — 避免断崖式下跌
    //   原：ssthresh = max(cwnd/2, kMinimumCwnd * MSS) — 每次丢包直接减半
    //   新：ssthresh = 0.5*ssthresh_old + 0.5*(cwnd/2) — EWMA 平滑
    //   效果：ssthresh 逐步收敛而非断崖下跌，cwnd 振荡幅度降低
    uint64_t new_ssthresh_raw = std::max(cwnd_bytes_ / 2, kMinimumCwnd * kMssBytes);
    // S3（K-BBRT-001）修复：ssthresh 封顶当前 cwnd。kMinimumCwnd=64（93KB，
    // relay 大帧演进）在小 cwnd 场景令下限反超丢包前窗口，fast recovery 后
    // cwnd 不减反增（实测 75920→97820）。丢包响应语义上 ssthresh 不得高于
    // 丢包时窗口；下限保底仅在收敛终点（recovery 退出）生效。
    new_ssthresh_raw = std::min(new_ssthresh_raw, cwnd_bytes_);
    if (ssthresh_ == UINT64_MAX) {
        // 首次设置 ssthresh（之前无丢包），直接用 raw 值
        ssthresh_ = new_ssthresh_raw;
    } else {
        // EWMA 平滑：50% 旧值 + 50% 新值
        ssthresh_ = ssthresh_ / 2 + new_ssthresh_raw / 2;
    }

    // NewReno fast recovery:
    // cwnd = ssthresh + 3*MSS (fast recovery inflation)
    cwnd_bytes_ = ssthresh_ + 3 * kMssBytes;
    in_recovery_ = true;
    // v1.7.0.7 H5/H6: 记录 recovery 起始 largest_acked，供 on_ack 退出判断
    // RFC 9002 §7.3.2: recovery 在所有 recovery 前的包被确认后退出
    recovery_start_pn_ = current_largest_acked;

    LINOH_INFO("NewReno::on_loss: cwnd=", cwnd_bytes_,
               " ssthresh=", ssthresh_,
               " recovery_start_pn=", recovery_start_pn_,
               " ewma_smoothed=", (ssthresh_ != new_ssthresh_raw));
}

void NewRenoController::on_rto() {
    // P9.1: 全程持 mu_ 锁 — 修改 cwnd/ssthresh/in_recovery
    std::lock_guard<std::mutex> lk(mu_);

    // P9.3 §4.3: on_rto cwnd 下限 — 原直接降到 2*MSS 过激
    //   原：cwnd = kMinimumCwnd * kMssBytes (2*1460=2920) — 断崖式下跌
    //   新：cwnd = max(kMinimumCwnd*MSS, cwnd/2) — 最多减半，不低于 2*MSS
    //   效果：RTO 后 cwnd 不会从 239824 直接降到 2920，而是降到 119912，
    //         避免 cwnd 振荡 > 10x
    ssthresh_ = std::max(cwnd_bytes_ / 2, kMinimumCwnd * kMssBytes);
    uint64_t cwnd_floor = kMinimumCwnd * kMssBytes;  // 2*MSS = 2920
    cwnd_bytes_ = std::max(cwnd_bytes_ / 2, cwnd_floor);  // P9.3: 最多减半
    in_recovery_ = false;

    LINOH_DEBUG("NewReno: on_rto, cwnd=", cwnd_bytes_,
                " ssthresh=", ssthresh_);
    // 埋点诊断 v1.5.0.2.6: cwnd RTO 重置量化, 量化 on_rto → cwnd 变化.
    // v1.5.0.2.7: ssthresh_=UINT64_MAX 时输出 "INF" (RFC 9002 §7.3.1 标准).
    if (ssthresh_ == UINT64_MAX) {
        LINOH_INFO("NewReno::on_rto: cwnd_reset=", cwnd_bytes_,
                   " ssthresh_after=INF",
                   " cwnd_floor=", cwnd_floor);
    } else {
        LINOH_INFO("NewReno::on_rto: cwnd_reset=", cwnd_bytes_,
                   " ssthresh_after=", ssthresh_,
                   " cwnd_floor=", cwnd_floor);
    }
}

bool NewRenoController::can_send(uint64_t bytes) const {
    // P9.1: 全程持 mu_ 锁 — 读 cwnd_bytes_/retx_pending_count_ 与 on_ack/on_loss 并发。
    //   不调用 is_cwnd_suppressed()（内部也取 mu_，重入死锁），直接判断。
    std::lock_guard<std::mutex> lk(mu_);

    // P10 修复（2026-08-10）：禁用 retx_pending cwnd 抑制
    //   根因：retx_pending > 100 时 return false，HEARTBEAT ACK 等小帧被完全阻塞，
    //         导致 win-worker JOIN 消息无法发送（retx_queue 积压 1218 包，cwnd=5840）。
    //   修复：移除 retx_pending 抑制逻辑，仅保留 cwnd_bytes_ 限制。
    //         拥塞控制仍由 cwnd_bytes_ 保证（on_ack/on_loss 动态调整），
    //         retx 队列由 Connection 层按 cwnd 配额调度，无需在 can_send 层二次抑制。
    //   影响：send_loop 在 retx backlog 高时仍可发送小帧（HEARTBEAT/JOIN/ACK），
    //         打破"retx 积压 → 小帧阻塞 → 无 ACK → retx 无法排空"死锁链。
    (void)retx_pending_count_;  // 显式标记未使用，避免编译警告
    (void)kCwndSuppressThreshold;
    (void)suppressed_since_ms_;
    (void)kSuppressMaxMs;
    return bytes <= cwnd_bytes_;
}

void NewRenoController::reset() {
    // P9.1: 全程持 mu_ 锁 — 修改所有拥塞控制状态
    std::lock_guard<std::mutex> lk(mu_);
    cwnd_bytes_ = kInitialCwndBytes;  // v1.5.0.1 P2-2: 严格 RFC 6928 IW10
    ssthresh_ = UINT64_MAX;
    in_recovery_ = false;
    recovery_start_pn_ = 0;
}

// P9.1: 以下 4 个 override 方法此前缺失定义（仅 hpp 声明 + 基类默认实现），
//   导致链接失败（undefined reference to NewRenoController::cwnd_bytes / is_cwnd_suppressed /
//   update_retx_pending / retx_pending_count_for_test）。补充定义并加 mu_ 锁。

uint64_t NewRenoController::cwnd_bytes() const {
    // P9.1: 加 mu_ 锁 — 读 cwnd_bytes_ 与 on_ack/on_loss/on_rto 并发
    std::lock_guard<std::mutex> lk(mu_);
    return cwnd_bytes_;
}

bool NewRenoController::is_cwnd_suppressed() const {
    // P9.1: 加 mu_ 锁 — 读 retx_pending_count_ 与 update_retx_pending 并发。
    //   供测试/外部查询调用；on_ack/can_send 持锁时直接判断条件，不调用本方法（避免重入）。
    std::lock_guard<std::mutex> lk(mu_);

    if (retx_pending_count_ <= kCwndSuppressThreshold) {
        return false;
    }

    // P9.2 层 1: 抑制态超时退出
    //   抑制超过 kSuppressMaxMs(5s) 后强制返回 false，打破死锁链
    if (suppressed_since_ms_ > 0.0) {
        double now = now_ms_steady();
        if (now - suppressed_since_ms_ > kSuppressMaxMs) {
            return false;  // 抑制超时，视为未抑制
        }
    }
    return true;
}

void NewRenoController::update_retx_pending(std::size_t count) {
    // P9.1: 加 mu_ 锁 — 写 retx_pending_count_ 与 is_cwnd_suppressed/can_send/on_ack 并发
    std::lock_guard<std::mutex> lk(mu_);

    // P9.2: 记录进入/退出抑制态的时间戳
    bool was_suppressed = retx_pending_count_ > kCwndSuppressThreshold;
    retx_pending_count_ = count;
    bool is_suppressed = retx_pending_count_ > kCwndSuppressThreshold;

    if (!was_suppressed && is_suppressed) {
        // 进入抑制态 — 记录时间戳
        suppressed_since_ms_ = now_ms_steady();
        LINOH_INFO("NewReno::update_retx_pending: ENTER suppress state, count=", count,
                   " threshold=", kCwndSuppressThreshold,
                   " suppressed_since_ms=", suppressed_since_ms_);
    } else if (was_suppressed && !is_suppressed) {
        // 退出抑制态 — 清除时间戳
        double duration = (suppressed_since_ms_ > 0.0)
                          ? (now_ms_steady() - suppressed_since_ms_) : 0.0;
        LINOH_INFO("NewReno::update_retx_pending: EXIT suppress state, count=", count,
                   " suppressed_duration_ms=", duration);
        suppressed_since_ms_ = 0.0;
    }
}

std::size_t NewRenoController::retx_pending_count_for_test() const {
    // P9.1: 加 mu_ 锁 — 读 retx_pending_count_
    std::lock_guard<std::mutex> lk(mu_);
    return retx_pending_count_;
}

} // namespace linoh::protocol
