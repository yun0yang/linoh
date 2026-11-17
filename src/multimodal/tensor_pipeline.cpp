// tensor_pipeline.cpp — v3.9.2 异步序列化流水线实现

#include "linoh/multimodal/tensor_pipeline.hpp"

#include <utility>

namespace linoh::multimodal {

TensorPipeline::TensorPipeline()
    : serialize_fn_(default_serialize) {
    serialize_thread_ = std::thread(&TensorPipeline::serialize_loop, this);
}

TensorPipeline::~TensorPipeline() {
    shutdown();
}

void TensorPipeline::submit(TensorId id, std::vector<std::uint8_t> raw_data) {
    if (shutting_down_.load()) {
        return;  // shutdown 后静默丢弃
    }
    {
        std::lock_guard<std::mutex> lk(queue_mutex_);
        raw_queue_.emplace(id, std::move(raw_data));
    }
    queue_cv_.notify_one();
}

std::optional<TensorPipeline::SerializedTensor> TensorPipeline::try_take(TensorId id) {
    std::lock_guard<std::mutex> lk(cache_mutex_);
    auto it = serialized_cache_.find(id);
    if (it == serialized_cache_.end()) {
        return std::nullopt;  // 未就绪
    }
    SerializedTensor result;
    result.id = id;
    result.data = std::move(it->second);
    serialized_cache_.erase(it);
    return result;
}

void TensorPipeline::set_serialize_fn(SerializeFn fn) {
    std::lock_guard<std::mutex> qlk(queue_mutex_);
    serialize_fn_ = fn ? std::move(fn) : default_serialize;
}

void TensorPipeline::shutdown() {
    bool expected = false;
    if (!shutting_down_.compare_exchange_strong(expected, true)) {
        return;  // 已经 shutdown
    }

    // 通知序列化线程检查 shutting_down_（可能正在 wait）
    queue_cv_.notify_all();

    // 等待序列化线程结束（会先排空 raw_queue_ 中剩余数据）
    if (serialize_thread_.joinable()) {
        serialize_thread_.join();
    }

    running_.store(false);
}

std::size_t TensorPipeline::pending_count() const {
    std::lock_guard<std::mutex> lk(queue_mutex_);
    return raw_queue_.size();
}

std::size_t TensorPipeline::ready_count() const {
    std::lock_guard<std::mutex> lk(cache_mutex_);
    return serialized_cache_.size();
}

void TensorPipeline::serialize_loop() {
    while (true) {
        // 从 raw_queue_ 取一个待序列化的 tensor
        std::pair<TensorId, std::vector<std::uint8_t>> item;
        {
            std::unique_lock<std::mutex> lk(queue_mutex_);
            queue_cv_.wait(lk, [this] {
                return !raw_queue_.empty() || shutting_down_.load();
            });

            if (raw_queue_.empty()) {
                // 队列空 + shutting_down → 退出
                if (shutting_down_.load()) {
                    return;
                }
                continue;  // spurious wake，继续等待
            }

            item = std::move(raw_queue_.front());
            raw_queue_.pop();
        }

        // 执行序列化（不持锁，允许 submit/try_take 并发）
        std::vector<std::uint8_t> serialized;
        try {
            // 复制 serialize_fn_ 的引用（避免长时间持锁）
            SerializeFn fn;
            {
                std::lock_guard<std::mutex> lk(queue_mutex_);
                fn = serialize_fn_;
            }
            serialized = fn(item.first, std::move(item.second));
        } catch (...) {
            // 序列化异常时用空数据兜底（不崩溃，上层通过 try_take 检测空数据）
            serialized.clear();
        }

        // 存入 serialized_cache_
        {
            std::lock_guard<std::mutex> lk(cache_mutex_);
            serialized_cache_[item.first] = std::move(serialized);
        }
    }
}

}  // namespace linoh::multimodal
