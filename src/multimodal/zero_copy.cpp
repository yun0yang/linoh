// zero_copy.cpp — 零拷贝 send/recv 路径实现（v1.6.0.3 / P2）

#include "linoh/multimodal/zero_copy.hpp"

#include <algorithm>
#include <cstring>

#include "linoh/multimodal/ep_channel.hpp"
#include "linoh/multimodal/ep_frames.hpp"

namespace linoh::multimodal::ep {

// ============================================================================
// ZeroCopySender
// ============================================================================

ZeroCopySender::ZeroCopySender(StaticBufferPool *pool,
                                EpChannel *channel,
                                const TensorShapeNegotiator *shape_negotiator)
    : pool_(pool), channel_(channel), shape_neg_(shape_negotiator) {}

BorrowedBuffer ZeroCopySender::acquire_buffer() {
    if (!pool_) return BorrowedBuffer();
    return pool_->acquire();
}

bool ZeroCopySender::send_dispatch(std::uint64_t tensor_id,
                                    std::uint64_t expert_id,
                                    std::uint64_t token_cnt,
                                    BorrowedBuffer &&buf,
                                    std::size_t used_bytes) {
    return send_internal_(tensor_id, expert_id, token_cnt,
                         std::move(buf), used_bytes, true);
}

bool ZeroCopySender::send_combine(std::uint64_t tensor_id,
                                   std::uint64_t expert_id,
                                   std::uint64_t token_cnt,
                                   BorrowedBuffer &&buf,
                                   std::size_t used_bytes) {
    return send_internal_(tensor_id, expert_id, token_cnt,
                         std::move(buf), used_bytes, false);
}

bool ZeroCopySender::send_internal_(std::uint64_t tensor_id,
                                     std::uint64_t expert_id,
                                     std::uint64_t token_cnt,
                                     BorrowedBuffer &&buf,
                                     std::size_t used_bytes,
                                     bool is_dispatch) {
    if (!pool_ || !buf) {
        std::lock_guard<std::mutex> lk(stats_mu_);
        ++stats_.pool_exhaust_total;
        return false;
    }

    // v1.7.0.7 H6: 校验 used_bytes <= buf.size()，避免 fill_padding_ 和 span 构造越界
    if (used_bytes > buf.size()) {
        std::lock_guard<std::mutex> lk(stats_mu_);
        ++stats_.pool_exhaust_total;
        return false;
    }

    // 填充 padding（如果 used_bytes < buf.size()）
    // 注意：padding 是 buffer 级别操作，与 channel 有效性无关
    fill_padding_(buf.data(), used_bytes);

    // 检查 channel 有效性
    if (!channel_) {
        std::lock_guard<std::mutex> lk(stats_mu_);
        ++stats_.pool_exhaust_total;
        return false;
    }

    // 通过 EpChannel 发送（直接引用 buf.data()，0 memcpy）
    bool ok = false;
    std::span<const std::uint8_t> payload(buf.data().data(), used_bytes);
    if (is_dispatch) {
        ok = channel_->send_dispatch(tensor_id, expert_id, token_cnt, payload);
    } else {
        ok = channel_->send_combine(tensor_id, expert_id, token_cnt, payload);
    }

    {
        std::lock_guard<std::mutex> lk(stats_mu_);
        if (ok) {
            ++stats_.send_total;
            stats_.send_bytes += used_bytes;
        } else {
            ++stats_.pool_exhaust_total;
        }
    }

    // buf 析构自动归还 pool
    return ok;
}

void ZeroCopySender::fill_padding_(std::span<std::uint8_t> buf,
                                    std::size_t used_bytes) {
    if (used_bytes >= buf.size()) return;
    if (shape_neg_ && shape_neg_->is_negotiated()) {
        // 使用协商后的 padded_bytes
        std::uint64_t padded = shape_neg_->padded_bytes();
        if (padded > used_bytes && padded <= buf.size()) {
            TensorShapeNegotiator::fill_padding_zero(buf, used_bytes, padded);
            {
                std::lock_guard<std::mutex> lk(stats_mu_);
                ++stats_.padding_fill_total;
            }
            return;
        }
    }
    // 无协商时填充到 buf.size()
    std::fill(buf.begin() + used_bytes, buf.end(), std::uint8_t{0});
    {
        std::lock_guard<std::mutex> lk(stats_mu_);
        ++stats_.padding_fill_total;
    }
}

ZeroCopyStats ZeroCopySender::stats() const {
    std::lock_guard<std::mutex> lk(stats_mu_);
    return stats_;
}

bool ZeroCopySender::is_valid() const noexcept {
    return pool_ != nullptr && channel_ != nullptr;
}

// ============================================================================
// ZeroCopyReceiver
// ============================================================================

ZeroCopyReceiver::ZeroCopyReceiver(StaticBufferPool *pool) : pool_(pool) {}

bool ZeroCopyReceiver::handle_dispatch_frame(const EpDispatchFrame &frame) {
    return handle_internal_(frame.tensor_id, frame.payload, true);
}

bool ZeroCopyReceiver::handle_combine_frame(const EpCombineFrame &frame) {
    return handle_internal_(frame.tensor_id, frame.payload, false);
}

bool ZeroCopyReceiver::handle_internal_(std::uint64_t tensor_id,
                                         std::span<const std::uint8_t> payload,
                                         bool is_dispatch) {
    (void)is_dispatch;  // dispatch/combine 处理逻辑相同
    if (!pool_ || payload.empty()) return false;

    auto buf = pool_->acquire();
    if (!buf) {
        std::lock_guard<std::mutex> lk(stats_mu_);
        ++stats_.pool_exhaust_total;
        return false;
    }

    // 拷贝 payload 到 pool buffer（接收侧仍需 1 次 memcpy）
    // P4 阶段通过 NVLink/CUDA IPC 实现完全零拷贝
    std::size_t copy_bytes = (std::min)(payload.size(), buf.size());
    std::memcpy(buf.data().data(), payload.data(), copy_bytes);

    {
        std::lock_guard<std::mutex> lk(stats_mu_);
        ++stats_.recv_total;
        stats_.recv_bytes += copy_bytes;
    }

    if (callback_) {
        callback_(tensor_id, std::move(buf), copy_bytes);
    }
    // buf 若未被 callback 移走，析构自动归还
    return true;
}

ZeroCopyStats ZeroCopyReceiver::stats() const {
    std::lock_guard<std::mutex> lk(stats_mu_);
    return stats_;
}

}  // namespace linoh::multimodal::ep
