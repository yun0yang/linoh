// ep_channel.cpp — EP 通道收发封装实现（v1.6.0.1 / P0 + v1.6.0.7 / P6 可靠性增强）
//
// 实现 EpChannel 的发送 / 接收 / 统计逻辑。
// 发送：open_stream + write(encode_frame) + finish_send
// 接收：accept_stream + read + decode + 路由到回调
// P6：dispatch/combine 帧入队 pending，等待对端 ACK；超时则重传，达上限则丢弃

#include "linoh/multimodal/ep_channel.hpp"

#include "linoh/util/logging.hpp"

#include <chrono>
#include <cstring>
#include <utility>

namespace linoh::multimodal::ep {

namespace {

/// 获取当前时间的毫秒表示（steady_clock，用于计算超时）
double now_ms_steady() noexcept {
    auto tp = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(
                  tp.time_since_epoch())
                  .count();
    return ms;
}

}  // namespace

EpChannel::EpChannel(std::shared_ptr<endpoint::Connection> data_conn)
    : conn_(std::move(data_conn)) {}

EpChannel::~EpChannel() {
    stop_resend_loop();
    stop_recv_loop();
}

// ============================================================================
// 发送 API
// ============================================================================

bool EpChannel::send_dispatch(std::uint64_t tensor_id,
                              std::uint64_t expert_id,
                              std::uint64_t token_cnt,
                              std::span<const std::uint8_t> payload,
                              std::span<const std::uint8_t> padding) {
    EpDispatchFrame frame;
    frame.tensor_id = tensor_id;
    frame.expert_id = expert_id;
    frame.token_cnt = token_cnt;
    frame.payload.assign(payload.begin(), payload.end());
    frame.padding.assign(padding.begin(), padding.end());

    auto encoded = encode_dispatch_frame(frame);
    // P6：入队 pending 等待 ACK，padding 单独保存便于重传时复用
    std::vector<std::uint8_t> pad_vec;
    pad_vec.assign(padding.begin(), padding.end());
    return enqueue_and_send_(EpFrameType::DISPATCH, tensor_id, expert_id, token_cnt,
                             std::move(encoded), std::move(pad_vec));
}

bool EpChannel::send_combine(std::uint64_t tensor_id,
                             std::uint64_t expert_id,
                             std::uint64_t token_cnt,
                             std::span<const std::uint8_t> payload) {
    EpCombineFrame frame;
    frame.tensor_id = tensor_id;
    frame.expert_id = expert_id;
    frame.token_cnt = token_cnt;
    frame.payload.assign(payload.begin(), payload.end());

    auto encoded = encode_combine_frame(frame);
    // P6：combine 无 padding
    return enqueue_and_send_(EpFrameType::COMBINE, tensor_id, expert_id, token_cnt,
                             std::move(encoded), {});
}

bool EpChannel::send_sync(std::uint64_t sync_id,
                          EpSyncOp sync_op,
                          std::uint64_t participant_mask,
                          std::span<const std::uint8_t> payload,
                          std::uint8_t reduce_op,
                          std::uint8_t algo,
                          std::uint16_t shard_idx,
                          std::uint16_t total_shards,
                          std::uint64_t from_node_id,
                          std::uint16_t step) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = sync_op;
    frame.participant_mask = participant_mask;
    frame.reduce_op = reduce_op;  // mp-M2 (v1.7.0.8): 传递 AllReduce 规约操作
    frame.algo = algo;            // v2.2 Phase 3 (P3-F): 传递集合通信算法
    frame.shard_idx = shard_idx;  // v2.2 Phase 3 (P3-G): 大 chunk 分片序号
    frame.total_shards = total_shards;  // v2.2 Phase 3 (P3-G): 总分片数
    frame.payload.assign(payload.begin(), payload.end());
    frame.from_node_id = from_node_id;  // v2.3 Phase 4 (P4-A): 发送方 bit position
    frame.step = step;                  // v2.3 Phase 4 (P4-A): 集合通信步数

    auto encoded = encode_sync_frame(frame);
    return send_frame_(encoded);
}

// ============================================================================
// P4 硬件加速 API
// ============================================================================

void EpChannel::set_hw_accel(net::TransportSelector *selector) noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    hw_selector_ = selector;
}

bool EpChannel::has_hw_accel() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return hw_selector_ != nullptr;
}

std::size_t EpChannel::try_send_hw_(net::NodeId peer, const net::CudaBuffer &buf) {
    net::TransportSelector *sel = nullptr;
    {
        std::lock_guard<std::mutex> lk(mu_);
        sel = hw_selector_;
    }
    if (!sel || !buf.valid()) {
        return 0;
    }
    auto transport = sel->select(peer);
    if (!transport) {
        return 0;
    }
    auto sent = transport->send_gpu(peer, buf);
    if (sent == 0) {
        record_hw_failure_();
        return 0;
    }
    return sent;
}

bool EpChannel::send_dispatch_hw(net::NodeId peer,
                                  std::uint64_t tensor_id,
                                  std::uint64_t expert_id,
                                  std::uint64_t token_cnt,
                                  const net::CudaBuffer &buf) {
    // 优先尝试 hw 路径
    auto hw_sent = try_send_hw_(peer, buf);
    if (hw_sent > 0) {
        record_hw_sent_(EpFrameType::DISPATCH, hw_sent);
        return true;
    }
    // 回退到 QUIC UDP
    record_hw_fallback_();
    if (!buf.valid()) {
        record_send_failure_();
        return false;
    }
    auto span = buf.as_span();
    return send_dispatch(tensor_id, expert_id, token_cnt, span);
}

bool EpChannel::send_combine_hw(net::NodeId peer,
                                 std::uint64_t tensor_id,
                                 std::uint64_t expert_id,
                                 std::uint64_t token_cnt,
                                 const net::CudaBuffer &buf) {
    auto hw_sent = try_send_hw_(peer, buf);
    if (hw_sent > 0) {
        record_hw_sent_(EpFrameType::COMBINE, hw_sent);
        return true;
    }
    record_hw_fallback_();
    if (!buf.valid()) {
        record_send_failure_();
        return false;
    }
    auto span = buf.as_span();
    return send_combine(tensor_id, expert_id, token_cnt, span);
}

// ============================================================================
// 回调注册
// ============================================================================

void EpChannel::set_callbacks(EpChannelCallbacks callbacks) {
    std::lock_guard<std::mutex> lk(cb_mu_);
    callbacks_ = std::move(callbacks);
}

// ============================================================================
// 接收循环
// ============================================================================

void EpChannel::start_recv_loop() {
    if (recv_running_.exchange(true)) {
        return;  // 已在运行
    }
    recv_stop_.store(false);
    recv_thread_ = std::thread([this] { recv_loop_(); });
}

void EpChannel::stop_recv_loop() {
    if (!recv_running_.load()) return;
    recv_stop_.store(true);
    if (recv_thread_.joinable()) {
        recv_thread_.join();
    }
    recv_running_.store(false);
}

void EpChannel::recv_loop_() {
    while (!recv_stop_.load() && conn_ && !conn_->is_closed()) {
        // accept_stream 阻塞等待新 stream
        auto stream = conn_->accept_stream();
        if (!stream) {
            // 连接关闭或出错
            break;
        }

        // mp-M1 (v1.7.0.8): per-stream 累积缓冲，避免半帧丢弃。
        //   原实现 read(0) 后立即 handle_frame_ + consume，若帧未完整到达，
        //   decode 失败直接 consume 掉部分数据，整帧永久丢失。
        //   现维护 accum 缓冲：read 追加到 accum + consume stream 缓冲，
        //   从 accum 尝试解码完整帧，成功才移除对应字节，失败保留等待更多数据。
        std::vector<std::uint8_t> accum;

        // 循环读取 stream 数据
        while (!recv_stop_.load() && !stream->is_closed()) {
            // 等待数据到达（简单轮询，P3 阶段再优化为事件驱动）
            if (stream->readable_size() == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }

            // 读取全部可读数据并追加到累积缓冲
            auto readable = stream->read(0);
            if (readable.empty()) {
                continue;
            }
            accum.insert(accum.end(), readable.begin(), readable.end());
            // 数据已拷贝到 accum，消费 stream 缓冲释放内存
            stream->consume(readable.size());

            // 循环从 accum 解码完整帧（可能缓冲中含多个帧）
            while (!accum.empty()) {
                std::span<const std::uint8_t> data(accum.data(), accum.size());
                std::size_t consumed = handle_frame_(data);
                if (consumed == 0) {
                    // 帧不完整，等待更多数据到达
                    // 防止内存爆炸：累积缓冲超上限视为垃圾数据/攻击，清空
                    if (accum.size() > kEpMaxAccumBuffer) {
                        LINOH_WARN("EpChannel: accum buffer overflow (",
                                   accum.size(), " bytes), clearing");
                        record_decode_failure_();
                        std::lock_guard<std::mutex> lk(cb_mu_);
                        if (callbacks_.on_decode_error) {
                            callbacks_.on_decode_error(
                                std::span<const std::uint8_t>(accum.data(), accum.size()));
                        }
                        accum.clear();
                    }
                    break;  // 等待下次 read 追加数据
                }
                // 消费已处理字节
                accum.erase(accum.begin(), accum.begin() + consumed);
            }
        }
    }
}

std::size_t EpChannel::handle_frame_(std::span<const std::uint8_t> data) {
    // mp-M1 (v1.7.0.8): 返回消费字节数，0 表示数据不完整需等待更多数据
    if (data.empty()) return 0;

    // 识别帧类型
    auto frame_type = peek_ep_frame_type(data);
    if (!frame_type) {
        // 首字节非法：丢弃 1 字节继续尝试（避免垃圾数据卡死累积缓冲）
        record_decode_failure_();
        std::lock_guard<std::mutex> lk(cb_mu_);
        if (callbacks_.on_decode_error) {
            callbacks_.on_decode_error(data.subspan(0, 1));
        }
        return 1;
    }

    switch (*frame_type) {
        case EpFrameType::DISPATCH: {
            auto frame = decode_dispatch_frame(data);
            if (!frame) {
                // mp-M1: 半帧或数据损坏，返回 0 等待更多数据（上限保护在 recv_loop_）
                return 0;
            }
            // 用 encode 重计算精确消费字节数（VarInt 编码确定性，len(encode)==decode 消费量）
            std::size_t consumed = encode_dispatch_frame(*frame).size();
            record_recv_(EpFrameType::DISPATCH, consumed);
            // P6：发送 ACK 给发送方（接收方 -> 发送方确认）
            // frame_seq 无法从 dispatch 帧字段获取（协议未携带），
            // 因此 ACK 以 tensor_id + frame_type 为关联依据，发送方在 handle_ack_ 中按 tensor_id 匹配
            send_ack_(0 /* frame_seq，dispatch 协议未携带，用 0 占位 */,
                      frame->tensor_id, EpFrameType::DISPATCH);
            std::lock_guard<std::mutex> lk(cb_mu_);
            if (callbacks_.on_dispatch_received) {
                callbacks_.on_dispatch_received(*frame);
            }
            return consumed;
        }
        case EpFrameType::COMBINE: {
            auto frame = decode_combine_frame(data);
            if (!frame) {
                return 0;  // mp-M1: 不完整
            }
            std::size_t consumed = encode_combine_frame(*frame).size();
            record_recv_(EpFrameType::COMBINE, consumed);
            // P6：发送 ACK
            send_ack_(0, frame->tensor_id, EpFrameType::COMBINE);
            std::lock_guard<std::mutex> lk(cb_mu_);
            if (callbacks_.on_combine_received) {
                callbacks_.on_combine_received(*frame);
            }
            return consumed;
        }
        case EpFrameType::SYNC: {
            auto frame = decode_sync_frame(data);
            if (!frame) {
                return 0;  // mp-M1: 不完整
            }
            std::size_t consumed = encode_sync_frame(*frame).size();
            record_recv_(EpFrameType::SYNC, consumed);
            std::lock_guard<std::mutex> lk(cb_mu_);
            if (callbacks_.on_sync_received) {
                callbacks_.on_sync_received(*frame);
            }
            return consumed;
        }
        case EpFrameType::ACK: {
            // P6：处理收到的 ACK 帧
            auto frame = decode_ack_frame(data);
            if (!frame) {
                return 0;  // mp-M1: 不完整
            }
            std::size_t consumed = encode_ack_frame(*frame).size();
            record_ack_recv_();
            handle_ack_(*frame);
            return consumed;
        }
    }
    // 未知帧类型，丢弃 1 字节
    return 1;
}

// ============================================================================
// 内部：发送一帧
// ============================================================================

bool EpChannel::send_frame_(const std::vector<std::uint8_t> &encoded) {
    if (!conn_ || conn_->is_closed()) {
        record_send_failure_();
        return false;
    }

    auto stream = conn_->acquire_rpc_stream();
    if (!stream) {
        record_send_failure_();
        return false;
    }

    // 写入编码后的帧字节
    stream->write(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
    stream->finish_send();

    // 归还 stream 到池（已 fin_sent 的不归还，由 release_rpc_stream 处理）
    conn_->release_rpc_stream(stream);

    // 统计
    auto frame_type = peek_ep_frame_type(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
    if (frame_type) {
        record_sent_(*frame_type, encoded.size());
    }

    return true;
}

// ============================================================================
// 统计更新
// ============================================================================

void EpChannel::record_sent_(EpFrameType type, std::size_t bytes) {
    std::lock_guard<std::mutex> lk(stats_mu_);
    switch (type) {
        case EpFrameType::DISPATCH: ++stats_.dispatch_sent; break;
        case EpFrameType::COMBINE:  ++stats_.combine_sent;  break;
        case EpFrameType::SYNC:     ++stats_.sync_sent;     break;
        case EpFrameType::ACK:      ++stats_.ack_sent;      break;  // P6
    }
    stats_.bytes_sent += bytes;
}

void EpChannel::record_recv_(EpFrameType type, std::size_t bytes) {
    std::lock_guard<std::mutex> lk(stats_mu_);
    switch (type) {
        case EpFrameType::DISPATCH: ++stats_.dispatch_recv; break;
        case EpFrameType::COMBINE:  ++stats_.combine_recv;  break;
        case EpFrameType::SYNC:     ++stats_.sync_recv;     break;
        // ACK 的 recv 统计在 handle_frame_ ACK case 中通过 record_ack_recv_() 单独累加
        case EpFrameType::ACK:      break;
    }
    stats_.bytes_recv += bytes;
}

void EpChannel::record_send_failure_() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.send_failures;
}

void EpChannel::record_decode_failure_() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.decode_failures;
}

void EpChannel::record_hw_sent_(EpFrameType type, std::size_t bytes) {
    std::lock_guard<std::mutex> lk(stats_mu_);
    switch (type) {
        case EpFrameType::DISPATCH: ++stats_.hw_dispatch_sent; break;
        case EpFrameType::COMBINE:  ++stats_.hw_combine_sent;  break;
        default: break;
    }
    stats_.hw_bytes_sent += bytes;
}

void EpChannel::record_hw_failure_() noexcept {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.hw_failures;
}

void EpChannel::record_hw_fallback_() noexcept {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.hw_fallback_to_quic;
}

EpChannelStats EpChannel::stats() const {
    std::lock_guard<std::mutex> lk(stats_mu_);
    return stats_;
}

bool EpChannel::is_valid() const noexcept {
    return conn_ && !conn_->is_closed();
}

// ============================================================================
// P6 可靠性实现（v1.6.0.7）
// ============================================================================

bool EpChannel::enqueue_and_send_(EpFrameType type,
                                   std::uint64_t tensor_id,
                                   std::uint64_t expert_id,
                                   std::uint64_t token_cnt,
                                   std::vector<std::uint8_t> encoded,
                                   std::vector<std::uint8_t> padding) {
    if (!conn_ || conn_->is_closed()) {
        record_send_failure_();
        return false;
    }

    // 分配序列号
    std::uint64_t seq = next_frame_seq_.fetch_add(1);

    // 创建 pending 条目
    // v1.7.0.7 multimodal H1: 改用 shared_ptr 管理，resend_ep_if_needed_ 锁外
    //   持有 shared_ptr 拷贝避免 clear_pending 并发释放导致 UAF
    auto pf = std::make_shared<EpPendingFrame>();
    pf->type = type;
    pf->frame_seq = seq;
    pf->tensor_id = tensor_id;
    pf->expert_id = expert_id;
    pf->token_cnt = token_cnt;
    pf->payload = std::move(encoded);
    pf->padding = std::move(padding);
    pf->send_time_ms = now_ms_steady();
    pf->resent_count = 0;
    pf->acked.store(false);

    // 首次发送
    bool sent_ok = send_frame_(pf->payload);
    if (!sent_ok) {
        // 首次发送失败：不入队，直接返回失败
        // （send_frame_ 已记录 send_failures）
        return false;
    }

    // 入队等待 ACK
    {
        std::lock_guard<std::mutex> lk(pending_mu_);
        pending_frames_.push_back(std::move(pf));
    }

    return true;
}

bool EpChannel::send_ack_(std::uint64_t frame_seq,
                          std::uint64_t tensor_id,
                          EpFrameType frame_type) {
    if (!conn_ || conn_->is_closed()) {
        return false;
    }

    EpAckFrame ack;
    ack.frame_seq = frame_seq;
    ack.tensor_id = tensor_id;
    ack.frame_type = frame_type;

    auto encoded = encode_ack_frame(ack);
    bool ok = send_frame_(encoded);
    if (ok) {
        record_ack_sent_();
    }
    return ok;
}

void EpChannel::handle_ack_(const EpAckFrame &ack) {
    // mp-M6 (v1.7.0.8): 批量确认同 tensor_id + frame_type 的所有 pending 帧，
    //   避免逐帧 ACK 导致冗余重传。原实现 break 一次只确认一个，
    //   同一 tensor 的多个分片帧需多次 ACK 才能全部确认，期间未确认帧会触发重传。
    //   语义：ACK 表示"该 tensor 的所有 dispatch/combine 帧已正确接收"。
    std::lock_guard<std::mutex> lk(pending_mu_);
    for (auto &pf : pending_frames_) {
        if (pf->tensor_id == ack.tensor_id && pf->type == ack.frame_type && !pf->acked.load()) {
            pf->acked.store(true);
        }
    }
}

void EpChannel::start_resend_loop() {
    if (resend_running_.exchange(true)) {
        return;  // 已在运行
    }
    resend_stop_.store(false);
    resend_thread_ = std::thread([this] { resend_loop_(); });
}

void EpChannel::stop_resend_loop() {
    if (!resend_running_.load()) return;
    resend_stop_.store(true);
    resend_cv_.notify_all();
    if (resend_thread_.joinable()) {
        resend_thread_.join();
    }
    resend_running_.store(false);
}

void EpChannel::resend_loop_() {
    while (!resend_stop_.load()) {
        // 25ms 节拍
        {
            std::unique_lock<std::mutex> lk(pending_mu_);
            resend_cv_.wait_for(lk, std::chrono::milliseconds(static_cast<int>(kEpResendCheckIntervalMs)),
                                [this] { return resend_stop_.load(); });
        }
        if (resend_stop_.load()) break;

        resend_ep_if_needed_();
    }
}

void EpChannel::resend_ep_if_needed_() {
    double now = now_ms_steady();

    // 收集需要重传和丢弃的帧（在锁内扫描，在锁外发送以避免死锁）
    // v1.7.0.7 multimodal H1: to_resend / to_drop 改为存 shared_ptr 拷贝，
    //   锁外访问期间即使 clear_pending() 并发清空 pending_frames_，
    //   to_resend / to_drop 中的 shared_ptr 仍持有引用，避免 UAF
    std::vector<std::shared_ptr<EpPendingFrame>> to_resend;
    std::vector<std::shared_ptr<EpPendingFrame>> to_drop;

    {
        std::lock_guard<std::mutex> lk(pending_mu_);
        for (auto it = pending_frames_.begin(); it != pending_frames_.end();) {
            auto &pf = *it;
            if (pf->acked.load()) {
                // 已 ACK，从队列移除
                it = pending_frames_.erase(it);
                continue;
            }

            // 计算超时
            double timeout_ms = (pf->type == EpFrameType::DISPATCH)
                                    ? kEpDispatchResendTimeoutMs
                                    : kEpCombineResendTimeoutMs;
            std::uint32_t max_resend = (pf->type == EpFrameType::DISPATCH)
                                           ? kEpDispatchMaxResendCount
                                           : kEpCombineMaxResendCount;

            double elapsed = now - pf->send_time_ms;
            if (elapsed < timeout_ms) {
                ++it;
                continue;
            }

            // 超时
            if (pf->resent_count >= max_resend) {
                // 达到最大重传次数，准备丢弃
                // 先从队列移除，避免重复处理；to_drop 持 shared_ptr 拷贝保持引用
                to_drop.push_back(pf);
                it = pending_frames_.erase(it);
            } else {
                // 需要重传；to_resend 持 shared_ptr 拷贝，锁外 resend_frame_ 安全
                to_resend.push_back(pf);
                ++it;
            }
        }
    }

    // 锁外重传（shared_ptr 保证 pf 生命周期，即使 pending_frames_ 被并发清空）
    for (auto &pf : to_resend) {
        resend_frame_(*pf);
    }

    // 锁外丢弃（触发回调）
    for (auto &pf : to_drop) {
        drop_frame_(pf);
    }
}

void EpChannel::resend_frame_(EpPendingFrame &pf) {
    if (!conn_ || conn_->is_closed()) {
        return;
    }

    // 重传 payload（已编码的完整帧）
    bool ok = send_frame_(pf.payload);
    if (ok) {
        ++pf.resent_count;
        pf.send_time_ms = now_ms_steady();  // 重置发送时间，等待下一轮超时
        record_resent_(pf.type);
    } else {
        // 重传失败：不增加 resent_count，下一轮再试
        // （send_frame_ 已记录 send_failures）
    }
}

void EpChannel::drop_frame_(std::shared_ptr<EpPendingFrame> pf) {
    if (!pf) return;
    record_resend_dropped_();

    // 触发回调（锁外）
    EpFrameType type = pf->type;
    std::uint64_t seq = pf->frame_seq;
    std::uint64_t tensor_id = pf->tensor_id;
    pf.reset();  // 释放引用（to_drop 中的最后一个引用，EpPendingFrame 析构）

    std::lock_guard<std::mutex> lk(cb_mu_);
    if (callbacks_.on_frame_dropped) {
        callbacks_.on_frame_dropped(type, seq, tensor_id);
    }
}

std::size_t EpChannel::pending_size() const {
    std::lock_guard<std::mutex> lk(pending_mu_);
    return pending_frames_.size();
}

void EpChannel::clear_pending() {
    std::lock_guard<std::mutex> lk(pending_mu_);
    pending_frames_.clear();
}

void EpChannel::record_partial_combine_() noexcept {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.combine_partial_total;
}

void EpChannel::record_resent_(EpFrameType type) noexcept {
    std::lock_guard<std::mutex> lk(stats_mu_);
    switch (type) {
        case EpFrameType::DISPATCH: ++stats_.dispatch_resent; break;
        case EpFrameType::COMBINE:  ++stats_.combine_resent;  break;
        default: break;
    }
}

void EpChannel::record_ack_sent_() noexcept {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.ack_sent;
}

void EpChannel::record_ack_recv_() noexcept {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.ack_recv;
}

void EpChannel::record_resend_dropped_() noexcept {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.resend_dropped;
}

}  // namespace linoh::multimodal::ep
