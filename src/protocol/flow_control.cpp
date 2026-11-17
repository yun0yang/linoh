/// @file flow_control.cpp
/// QUIC 流量控制帧编解码 + FlowController 窗口管理实现。

#include "linoh/protocol/flow_control.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <cstring>

namespace linoh::protocol {

// ============================================================================
// FlowController
// ============================================================================

FlowController::FlowController(
    std::uint64_t initial_conn_window,
    std::uint64_t initial_stream_window,
    std::uint64_t max_bidi_streams,
    std::uint64_t max_uni_streams)
    : local_conn_window_(initial_conn_window)
    , conn_bytes_recv_(0)
    , remote_conn_window_(initial_conn_window)
    , conn_bytes_sent_(0)
    , local_max_bidi_streams_(max_bidi_streams)
    , local_max_uni_streams_(max_uni_streams)
    , remote_max_bidi_streams_(0)
    , remote_max_uni_streams_(0) {
    // 默认 per-stream 窗口不会预分配，按需在 on_remote_max_stream_data / local_stream_window 中添加
}

// v1.7.0.7 H4: _locked_ 内部方法实现（调用方已持 mu_）
std::uint64_t FlowController::conn_send_capacity_locked_() const {
    if (remote_conn_window_ > conn_bytes_sent_) {
        return remote_conn_window_ - conn_bytes_sent_;
    }
    return 0;
}

std::uint64_t FlowController::remote_stream_window_locked_(std::uint64_t stream_id) const {
    // mp-P4 (v1.7.0.8): unordered_map O(1) 查找替代 vector O(N) 线性扫描
    auto it = remote_stream_windows_.find(stream_id);
    if (it != remote_stream_windows_.end()) return it->second;
    // 未收到 MAX_STREAM_DATA 的 stream，使用默认窗口
    return kDefaultStreamWindow;
}

std::uint64_t FlowController::local_stream_window_locked_(std::uint64_t stream_id) const {
    // mp-P4 (v1.7.0.8): unordered_map O(1) 查找替代 vector O(N) 线性扫描
    auto it = local_stream_windows_.find(stream_id);
    if (it != local_stream_windows_.end()) return it->second;
    return kDefaultStreamWindow;
}

std::uint64_t FlowController::conn_send_capacity() const {
    std::lock_guard<std::mutex> lk(mu_);
    return conn_send_capacity_locked_();
}

void FlowController::on_conn_bytes_sent(std::uint64_t n) {
    // v1.7.0.7 H4: on_conn_bytes_sent 内部调用 conn_send_capacity，
    //   若 public 版本加锁会递归死锁，故调用 _locked_ 版本
    std::lock_guard<std::mutex> lk(mu_);
    conn_bytes_sent_ += n;
    LINOH_DEBUG("FlowController: conn_bytes_sent=", conn_bytes_sent_,
                " remote_window=", remote_conn_window_,
                " capacity=", conn_send_capacity_locked_());
}

void FlowController::on_remote_max_data(std::uint64_t new_window) {
    std::lock_guard<std::mutex> lk(mu_);
    if (new_window > remote_conn_window_) {
        remote_conn_window_ = new_window;
        LINOH_DEBUG("FlowController: remote MAX_DATA=", new_window);
    }
}

void FlowController::on_conn_bytes_recv(std::uint64_t n) {
    std::lock_guard<std::mutex> lk(mu_);
    conn_bytes_recv_ += n;
}

bool FlowController::should_send_max_data() const {
    // v1.5.0.1 P3-1: 比较 last_advertised_max_data_ 与 local_conn_window_，
    // 变化时返回 true（用于 1Hz 周期主动通告语义）。
    // 之前是 "consumed > window/2" 判定（按需扩张），但 P3-1 改为"窗口有变化
    // 就通告"（防御性主动通告，对端拿到最新窗口不用等 DATA_BLOCKED）。
    // 首次触发时 last_advertised_max_data_=0 < local_conn_window_(1MB)，返回 true。
    std::lock_guard<std::mutex> lk(mu_);
    return local_conn_window_ != last_advertised_max_data_;
}

std::uint64_t FlowController::next_max_data_value() const {
    // v1.5.0.1 6-3 fix: 窗口推进策略从 "local_conn_window_*2 + recv" 改为 "recv + 16MB"
    // 原策略 local_conn_window_*2 + conn_bytes_recv_ = 2MB + recv 只给 2MB headroom，
    // 5% 丢包下 retx 消耗 > 2MB 后 connection-level window 耗尽死锁。
    // 新策略 conn_bytes_recv_ + 16MB headroom，保证 retx 有足够空间。
    // 16MB = kDefaultConnWindow(1MB) * 16，与 stream-level 4MB 增量对称。
    std::lock_guard<std::mutex> lk(mu_);
    return conn_bytes_recv_ + kDefaultConnWindow * 16;  // recv + 16MB
}

void FlowController::mark_max_data_advertised(std::uint64_t advertised_value) {
    std::lock_guard<std::mutex> lk(mu_);
    last_advertised_max_data_ = advertised_value;
}

std::uint64_t FlowController::remote_stream_window(std::uint64_t stream_id) const {
    std::lock_guard<std::mutex> lk(mu_);
    return remote_stream_window_locked_(stream_id);
}

void FlowController::on_remote_max_stream_data(std::uint64_t stream_id, std::uint64_t new_window) {
    // mp-P4 (v1.7.0.8): unordered_map O(1) 查找/插入替代 vector O(N) 线性扫描
    std::lock_guard<std::mutex> lk(mu_);
    auto it = remote_stream_windows_.find(stream_id);
    if (it != remote_stream_windows_.end()) {
        if (new_window > it->second) it->second = new_window;
    } else {
        remote_stream_windows_.emplace(stream_id, new_window);
    }
}

// v5.4 F4：credit 预约保障——接收授权窗口至少提到 at_least（只升不降）
void FlowController::grant_stream_window(std::uint64_t stream_id, std::uint64_t at_least) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = local_stream_windows_.find(stream_id);
    if (it != local_stream_windows_.end()) {
        if (at_least > it->second) it->second = at_least;
    } else {
        local_stream_windows_.emplace(stream_id, at_least);
    }
}

std::uint64_t FlowController::stream_send_capacity(std::uint64_t stream_id,
                                                     std::uint64_t stream_send_offset) const {
    // v1.7.0.7 H4: stream_send_capacity 内部调用 remote_stream_window + conn_send_capacity，
    //   若 public 版本加锁会递归死锁，故调用 _locked_ 版本
    std::lock_guard<std::mutex> lk(mu_);
    std::uint64_t stream_window = remote_stream_window_locked_(stream_id);
    std::uint64_t conn_cap = conn_send_capacity_locked_();
    if (stream_window > stream_send_offset) {
        std::uint64_t stream_cap = stream_window - stream_send_offset;
        return std::min(stream_cap, conn_cap);
    }
    return 0;
}

std::uint64_t FlowController::local_stream_window(std::uint64_t stream_id) const {
    std::lock_guard<std::mutex> lk(mu_);
    return local_stream_window_locked_(stream_id);
}

void FlowController::on_stream_bytes_recv(std::uint64_t stream_id, std::uint64_t n) {
    // 更新 local stream window tracking — v1.5.0.1 P3-1:
    // 之前 on_stream_bytes_recv 是 no-op（找不到 sid 就 return），导致
    // should_send_max_stream_data 永远 true，emit_periodic_flow_control
    // 无法从 flow_ctrl_ 内部拿到"哪些 stream 需要通告"列表。
    // 修复：第一次见 sid 时 emplace(sid, n)；之后累加 n（recv 累计字节数）。
    // mp-P4 (v1.7.0.8): unordered_map O(1) 查找/插入替代 vector O(N) 线性扫描
    std::lock_guard<std::mutex> lk(mu_);
    auto it = local_stream_windows_.find(stream_id);
    if (it != local_stream_windows_.end()) {
        it->second += n;  // 累加已接收字节数（用于 should_send 判定）
    } else {
        local_stream_windows_.emplace(stream_id, n);
    }
}

std::vector<std::uint64_t> FlowController::local_stream_ids() const {
    // mp-P4 (v1.7.0.8): 从 unordered_map 收集 keys 排序返回
    //   原 vector 可直接遍历 pair.first，map 需遍历 iterator->first，复杂度不变。
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<std::uint64_t> ids;
    ids.reserve(local_stream_windows_.size());
    for (const auto &[sid, recv] : local_stream_windows_) {
        ids.push_back(sid);
    }
    std::sort(ids.begin(), ids.end());  // 升序（FIFO，避免饥饿）
    return ids;
}

bool FlowController::should_send_max_stream_data(std::uint64_t stream_id) const {
    // mp-L7 (v1.7.0.8): per-stream last_advertised 跟踪，避免无意义重复通告。
    //   原实现恒返回 true，每次 1Hz 周期任务都为每个 stream 发 MAX_STREAM_DATA，
    //   即使窗口未推进（recv 未增长）也发，浪费带宽 + 帧配额。
    //   修复：仅当 (next_value - last_advertised) > kDefaultStreamWindow/4 (64KB)
    //   时才返回 true，即窗口推进超过 1/4 默认窗口才触发通告。
    //   阈值 64KB 平衡灵敏度与开销：太小→频繁通告；太大→发送方窗口耗尽等待久。
    std::lock_guard<std::mutex> lk(mu_);
    std::uint64_t next_value = local_stream_window_locked_(stream_id) + kDefaultStreamWindow * 16;
    // mp-P4 (v1.7.0.8): unordered_map O(1) 查找替代 vector O(N) 线性扫描
    std::uint64_t last_adv = 0;
    auto it = last_advertised_stream_data_.find(stream_id);
    if (it != last_advertised_stream_data_.end()) last_adv = it->second;
    // 阈值：四分之一默认窗口（64KB）
    constexpr std::uint64_t kAdvertiseThreshold = kDefaultStreamWindow / 4;
    return (next_value > last_adv) && ((next_value - last_adv) >= kAdvertiseThreshold);
}

std::uint64_t FlowController::next_max_stream_data_value(std::uint64_t stream_id) const {
    // v1.5.0.1 6-3 fix: 窗口推进策略从 "recv*2 翻倍" 改为 "recv + 16*window 增量"
    // 原策略 recv*2 在 5% 丢包下增长太慢（每秒翻倍但 recv 增长慢，client 窗口耗尽死锁）
    // 新策略每次通告 max = recv + 4MB（16*256KB），保证 client 有足够发送+重传空间
    // 32MB 数据 / 4MB增量 = 8 次通告，1Hz emit 下 8 秒可通告完（0% drop）
    // 5% drop 下 recv 增长慢但增量固定 4MB，client 总有 4MB 空间可用
    // v1.7.0.7 H4: next_max_stream_data_value 内部调用 local_stream_window，
    //   若 public 版本加锁会递归死锁，故调用 _locked_ 版本
    // mp-L7 (v1.7.0.8): 不在此 const 方法中修改 last_advertised_stream_data_，
    //   改由调用方通过 mark_stream_data_advertised() 显式标记，分离计算与状态更新职责
    std::lock_guard<std::mutex> lk(mu_);
    std::uint64_t value = local_stream_window_locked_(stream_id) + kDefaultStreamWindow * 16;
    return value;
}

void FlowController::mark_stream_data_advertised(std::uint64_t stream_id, std::uint64_t advertised_value) {
    // mp-L7 (v1.7.0.8): 由调用方在 encode 完 MAX_STREAM_DATA 帧后调用
    // mp-P4 (v1.7.0.8): unordered_map O(1) 查找/插入替代 vector O(N) 线性扫描
    std::lock_guard<std::mutex> lk(mu_);
    auto it = last_advertised_stream_data_.find(stream_id);
    if (it != last_advertised_stream_data_.end()) {
        it->second = advertised_value;
    } else {
        last_advertised_stream_data_.emplace(stream_id, advertised_value);
    }
}

void FlowController::on_remote_max_bidi_streams(std::uint64_t n) {
    std::lock_guard<std::mutex> lk(mu_);
    if (n > remote_max_bidi_streams_) {
        remote_max_bidi_streams_ = n;
        LINOH_DEBUG("FlowController: remote MAX_STREAMS_BIDI=", n);
    }
}

void FlowController::on_remote_max_uni_streams(std::uint64_t n) {
    std::lock_guard<std::mutex> lk(mu_);
    if (n > remote_max_uni_streams_) {
        remote_max_uni_streams_ = n;
        LINOH_DEBUG("FlowController: remote MAX_STREAMS_UNI=", n);
    }
}

bool FlowController::can_open_bidi_stream(std::uint64_t current_count) const {
    std::lock_guard<std::mutex> lk(mu_);
    return current_count < remote_max_bidi_streams_;
}

bool FlowController::can_open_uni_stream(std::uint64_t current_count) const {
    std::lock_guard<std::mutex> lk(mu_);
    return current_count < remote_max_uni_streams_;
}

// ============================================================================
// Frame encoding
// ============================================================================

std::vector<std::uint8_t> encode_max_data(const MaxDataFrame &frame) {
    std::vector<std::uint8_t> buf;
    buf.push_back(0x10);  // type
    auto enc = util::varint_encode_vec(frame.maximum_data);
    buf.insert(buf.end(), enc.begin(), enc.end());
    return buf;
}

std::optional<MaxDataFrame> decode_max_data(std::span<const std::uint8_t> payload) {
    auto result = util::varint_decode(payload);
    if (!result) return std::nullopt;
    return MaxDataFrame{result->first};
}

std::vector<std::uint8_t> encode_max_stream_data(const MaxStreamDataFrame &frame) {
    std::vector<std::uint8_t> buf;
    buf.push_back(0x11);  // type
    auto sid = util::varint_encode_vec(frame.stream_id);
    buf.insert(buf.end(), sid.begin(), sid.end());
    auto msd = util::varint_encode_vec(frame.maximum_stream_data);
    buf.insert(buf.end(), msd.begin(), msd.end());
    return buf;
}

std::optional<MaxStreamDataFrame> decode_max_stream_data(std::span<const std::uint8_t> payload) {
    auto r1 = util::varint_decode(payload);
    if (!r1) return std::nullopt;
    if (payload.size() < r1->second) return std::nullopt;

    auto r2 = util::varint_decode(payload.subspan(r1->second));
    if (!r2) return std::nullopt;

    return MaxStreamDataFrame{r1->first, r2->first};
}

std::vector<std::uint8_t> encode_max_streams(const MaxStreamsFrame &frame) {
    std::vector<std::uint8_t> buf;
    buf.push_back(frame.bidirectional ? 0x12 : 0x13);
    auto enc = util::varint_encode_vec(frame.maximum_streams);
    buf.insert(buf.end(), enc.begin(), enc.end());
    return buf;
}

std::optional<MaxStreamsFrame> decode_max_streams(std::uint8_t frame_type,
                                                   std::span<const std::uint8_t> payload) {
    bool bidi;
    if (frame_type == 0x12) bidi = true;
    else if (frame_type == 0x13) bidi = false;
    else return std::nullopt;

    auto result = util::varint_decode(payload);
    if (!result) return std::nullopt;
    return MaxStreamsFrame{result->first, bidi};
}

std::vector<std::uint8_t> encode_data_blocked(const DataBlockedFrame &frame) {
    std::vector<std::uint8_t> buf;
    buf.push_back(0x14);  // type
    auto enc = util::varint_encode_vec(frame.maximum_data);
    buf.insert(buf.end(), enc.begin(), enc.end());
    return buf;
}

std::optional<DataBlockedFrame> decode_data_blocked(std::span<const std::uint8_t> payload) {
    auto result = util::varint_decode(payload);
    if (!result) return std::nullopt;
    return DataBlockedFrame{result->first};
}

std::vector<std::uint8_t> encode_stream_data_blocked(const StreamDataBlockedFrame &frame) {
    std::vector<std::uint8_t> buf;
    buf.push_back(0x15);  // type
    auto sid = util::varint_encode_vec(frame.stream_id);
    buf.insert(buf.end(), sid.begin(), sid.end());
    auto msd = util::varint_encode_vec(frame.maximum_stream_data);
    buf.insert(buf.end(), msd.begin(), msd.end());
    return buf;
}

std::optional<StreamDataBlockedFrame> decode_stream_data_blocked(std::span<const std::uint8_t> payload) {
    auto r1 = util::varint_decode(payload);
    if (!r1) return std::nullopt;

    auto r2 = util::varint_decode(payload.subspan(r1->second));
    if (!r2) return std::nullopt;

    return StreamDataBlockedFrame{r1->first, r2->first};
}

std::vector<std::uint8_t> encode_streams_blocked(const StreamsBlockedFrame &frame) {
    std::vector<std::uint8_t> buf;
    buf.push_back(frame.bidirectional ? 0x16 : 0x17);
    auto enc = util::varint_encode_vec(frame.maximum_streams);
    buf.insert(buf.end(), enc.begin(), enc.end());
    return buf;
}

std::optional<StreamsBlockedFrame> decode_streams_blocked(std::uint8_t frame_type,
                                                           std::span<const std::uint8_t> payload) {
    bool bidi;
    if (frame_type == 0x16) bidi = true;
    else if (frame_type == 0x17) bidi = false;
    else return std::nullopt;

    auto result = util::varint_decode(payload);
    if (!result) return std::nullopt;
    return StreamsBlockedFrame{result->first, bidi};
}

} // namespace linoh::protocol
