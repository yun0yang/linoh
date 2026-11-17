// zero_copy.hpp — 零拷贝 send/recv 路径（v1.6.0.3 / P2）
//
// 借鉴 MoonEP 思想 ③（零拷贝 NVLink 对称内存）的 CPU 侧实现：
//   - ZeroCopySender: 从 pool acquire buffer -> 填充数据 -> write_scatter 发送
//   - ZeroCopyReceiver: 接收数据 -> 写入 pool buffer -> 通知应用层
//
// P2 阶段定位：
//   - 消除 TensorStreamer 分片时的多次 memcpy
//   - pool buffer 直接作为 write_scatter 输入（0 次 memcpy 到 QUIC send buffer）
//   - 接收侧写入 pool buffer（0 次 memcpy 出 QUIC recv buffer）
//
// 与 v1.5.x 对比：
//   - v1.5.x: 4 次 memcpy + 2 次 GPU<->CPU 拷贝
//   - v1.6.0.3: 0 次 memcpy + 2 次 GPU<->CPU 拷贝（P4 阶段实现完全零拷贝）
//
// 与 EpChannel 集成：
//   - ZeroCopySender 持有 StaticBufferPool 引用
//   - send_dispatch_zc 内部调用 ZeroCopySender::send
//   - 应用层通过回调接收数据（ZeroCopyReceiver::set_callback）

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

#include "linoh/multimodal/buffer_pool.hpp"
#include "linoh/multimodal/static_shape.hpp"

namespace linoh::multimodal::ep {

/// 前向声明
class EpChannel;

/// 零拷贝统计
struct ZeroCopyStats {
    std::uint64_t send_total{0};         // 发送次数
    std::uint64_t send_bytes{0};          // 发送字节数
    std::uint64_t recv_total{0};          // 接收次数
    std::uint64_t recv_bytes{0};          // 接收字节数
    std::uint64_t pool_exhaust_total{0};  // pool 耗尽次数（send 路径）
    std::uint64_t padding_fill_total{0};  // padding 填充次数
};

/// 零拷贝发送器
///
/// 用法：
///   ZeroCopySender sender(&pool, &channel);
///   auto buf = sender.acquire_buffer();
///   // 填充 buf.data()
///   sender.send_dispatch(tensor_id, expert_id, token_cnt, std::move(buf), used_bytes);
class ZeroCopySender {
public:
    /// 构造
    /// \param pool StaticBufferPool 引用（必须 outlive sender）
    /// \param channel EpChannel 引用（必须 outlive sender）
    /// \param shape_negotiator 形状协商器（可选，用于 padding 计算）
    ZeroCopySender(StaticBufferPool *pool,
                   EpChannel *channel,
                   const TensorShapeNegotiator *shape_negotiator = nullptr);

    /// 从 pool acquire 一个 buffer（用于填充数据）
    /// \return 有效 BorrowedBuffer；pool 耗尽返回空
    BorrowedBuffer acquire_buffer();

    /// 发送 EP_DISPATCH_FRAME（零拷贝路径）
    /// \param tensor_id tensor ID
    /// \param expert_id 专家 ID
    /// \param token_cnt token 数
    /// \param buf 借出的 buffer（数据已填充）
    /// \param used_bytes 实际使用字节数（< buf.size() 时填充 padding）
    /// \return true=发送成功，false=发送失败
    bool send_dispatch(std::uint64_t tensor_id,
                       std::uint64_t expert_id,
                       std::uint64_t token_cnt,
                       BorrowedBuffer &&buf,
                       std::size_t used_bytes);

    /// 发送 EP_COMBINE_FRAME（零拷贝路径）
    bool send_combine(std::uint64_t tensor_id,
                      std::uint64_t expert_id,
                      std::uint64_t token_cnt,
                      BorrowedBuffer &&buf,
                      std::size_t used_bytes);

    /// 获取统计
    ZeroCopyStats stats() const;

    /// 是否有效（pool 和 channel 非空）
    bool is_valid() const noexcept;

private:
    StaticBufferPool *pool_;
    EpChannel *channel_;
    const TensorShapeNegotiator *shape_neg_;

    mutable std::mutex stats_mu_;
    ZeroCopyStats stats_;

    /// 内部：填充 padding 并发送
    bool send_internal_(std::uint64_t tensor_id,
                        std::uint64_t expert_id,
                        std::uint64_t token_cnt,
                        BorrowedBuffer &&buf,
                        std::size_t used_bytes,
                        bool is_dispatch);

    /// 填充 padding（如果 used_bytes < buf.size()）
    void fill_padding_(std::span<std::uint8_t> buf, std::size_t used_bytes);
};

/// 零拷贝接收器
///
/// 用法：
///   ZeroCopyReceiver receiver(&pool);
///   receiver.set_callback([](uint64_t tensor_id, BorrowedBuffer buf, TensorMeta meta) {
///       // 处理 buf.data() 中的数据
///   });
///   // EpChannel 的 on_dispatch_received 回调中调用
///   receiver.handle_dispatch_frame(frame);
class ZeroCopyReceiver {
public:
    /// 接收回调（tensor_id + 借出的 buffer + 实际字节数）
    using RecvCallback = std::function<void(std::uint64_t tensor_id,
                                            BorrowedBuffer buf,
                                            std::size_t used_bytes)>;

    /// 构造
    /// \param pool StaticBufferPool 引用（必须 outlive receiver）
    ZeroCopyReceiver(StaticBufferPool *pool);

    /// 设置回调
    void set_callback(RecvCallback cb) { callback_ = std::move(cb); }

    /// 处理 EP_DISPATCH_FRAME（从 EpChannel 回调调用）
    /// \param frame 接收到的 dispatch 帧
    /// \return true=处理成功，false=pool 耗尽
    bool handle_dispatch_frame(const struct EpDispatchFrame &frame);

    /// 处理 EP_COMBINE_FRAME
    /// \return true=处理成功，false=pool 耗尽
    bool handle_combine_frame(const struct EpCombineFrame &frame);

    /// 获取统计
    ZeroCopyStats stats() const;

private:
    StaticBufferPool *pool_;
    RecvCallback callback_;

    mutable std::mutex stats_mu_;
    ZeroCopyStats stats_;

    /// 内部处理（dispatch/combine 共用）
    bool handle_internal_(std::uint64_t tensor_id,
                          std::span<const std::uint8_t> payload,
                          bool is_dispatch);
};

}  // namespace linoh::multimodal::ep
