// tensor_pipeline.hpp — v3.9.2 异步序列化流水线
//
// 三阶段流水线设计，序列化不阻塞推理线程：
//   阶段 1 (推理线程)：submit(id, raw_data) → 投递到 raw_queue_（非阻塞，立即返回）
//   阶段 2 (序列化线程)：raw_queue_ → serialize_fn → serialized_cache_（异步，独立线程）
//   阶段 3 (发送线程)：try_take(id) → 从 serialized_cache_ 取已序列化数据（非阻塞）
//
// 设计要点：
//   - submit / try_take 均非阻塞，推理线程和发送线程不会被序列化阻塞
//   - 支持乱序提交、乱序取走（按 tensor_id 索引）
//   - 序列化函数可定制（默认 identity 直接传递，可设为 TensorShardMessage::serialize 等）
//   - shutdown 等待队列排空后 join 序列化线程
//   - 线程安全：queue_mutex_ 保护 raw_queue_，cache_mutex_ 保护 serialized_cache_

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>
#include <unordered_map>
#include <vector>

namespace linoh::multimodal {

/// 异步序列化流水线（v3.9.2）
///
/// 将 tensor 序列化从推理线程剥离到独立序列化线程，避免大 tensor 序列化阻塞推理。
/// 三阶段流水线：submit（投递 raw）→ 异步序列化 → try_take（取已序列化）。
class TensorPipeline {
public:
    using TensorId = std::uint64_t;

    /// 序列化函数类型：接收 (tensor_id, raw_data)，返回序列化后的字节流
    /// 默认为 identity（直接传递 raw_data），可设为 TensorShardMessage::serialize 等
    using SerializeFn = std::function<std::vector<std::uint8_t>(
        TensorId, std::vector<std::uint8_t>)>;

    /// 已序列化的 tensor 数据
    struct SerializedTensor {
        TensorId id{0};
        std::vector<std::uint8_t> data;
    };

    /// 构造：启动序列化线程
    TensorPipeline();

    /// 析构：自动 shutdown（等待队列排空 + join 线程）
    ~TensorPipeline();

    // 不可拷贝（内部有线程 + mutex）
    TensorPipeline(const TensorPipeline &) = delete;
    TensorPipeline &operator=(const TensorPipeline &) = delete;

    // 不可移动（内部序列化线程绑定 this 指针，移动后线程引用失效）
    // 如需转移所有权，使用 std::unique_ptr<TensorPipeline>
    TensorPipeline(TensorPipeline &&) = delete;
    TensorPipeline &operator=(TensorPipeline &&) = delete;

    // ===== 阶段 1：投递 raw 数据（推理线程调用，非阻塞）=====

    /// 投递 raw tensor 数据到序列化队列
    /// \param id tensor 唯一标识
    /// \param raw_data 原始数据（所有权转移给流水线）
    /// \note 非阻塞：投递后立即返回，序列化在后台线程异步执行
    void submit(TensorId id, std::vector<std::uint8_t> raw_data);

    // ===== 阶段 3：取已序列化数据（发送线程调用，非阻塞）=====

    /// 尝试取已序列化的 tensor 数据
    /// \param id tensor 唯一标识
    /// \return 若已序列化完成则返回数据（并从缓存移除），否则返回 nullopt
    /// \note 非阻塞：未就绪时立即返回 nullopt，不等待
    std::optional<SerializedTensor> try_take(TensorId id);

    // ===== 配置 =====

    /// 设置自定义序列化函数（可选）
    /// \param fn 序列化函数，接收 (id, raw_data) 返回序列化字节流
    /// \note 默认 identity 直接传递 raw_data。可在 submit 前设置。
    ///       例如设置为 TensorShardMessage::serialize 封装。
    void set_serialize_fn(SerializeFn fn);

    // ===== 生命周期 =====

    /// 关闭流水线：标记停止接收 → 等待 raw_queue 排空 → join 序列化线程
    /// \note shutdown 后 submit 不再接受新数据（静默丢弃）
    void shutdown();

    // ===== 查询 =====

    /// raw_queue 中等待序列化的数量
    std::size_t pending_count() const;

    /// serialized_cache 中已就绪待取的数量
    std::size_t ready_count() const;

    /// 序列化线程是否正在运行
    bool is_running() const noexcept { return running_.load(); }

    /// 是否已 shutdown
    bool is_shutdown() const noexcept { return shutting_down_.load(); }

private:
    /// 序列化线程主循环
    void serialize_loop();

    /// 默认序列化函数（identity：直接传递 raw_data）
    static std::vector<std::uint8_t> default_serialize(
        TensorId /*id*/, std::vector<std::uint8_t> raw_data) {
        return raw_data;
    }

    // ===== raw_queue_（阶段 1 → 阶段 2）=====
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<std::pair<TensorId, std::vector<std::uint8_t>>> raw_queue_;

    // ===== serialized_cache_（阶段 2 → 阶段 3）=====
    mutable std::mutex cache_mutex_;
    std::unordered_map<TensorId, std::vector<std::uint8_t>> serialized_cache_;

    // ===== 序列化函数 =====
    SerializeFn serialize_fn_;

    // ===== 线程控制 =====
    std::atomic<bool> running_{true};      // 序列化线程是否运行
    std::atomic<bool> shutting_down_{false}; // 是否正在 shutdown
    std::thread serialize_thread_;
};

}  // namespace linoh::multimodal
