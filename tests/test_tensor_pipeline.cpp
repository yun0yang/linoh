// test_tensor_pipeline.cpp — v3.9.2 异步序列化流水线测试
//
// 覆盖场景：
//   1. 基本 submit→try_take 流程
//   2. try_take 未就绪返回 nullopt
//   3. submit 非阻塞
//   4. 乱序提交/取走
//   5. 自定义序列化函数
//   6. shutdown 后 submit 丢弃
//   7. shutdown 排空队列
//   8. pending_count/ready_count 查询
//   9. 序列化不阻塞推理线程（时间验证）
//   10. 多线程并发 submit + try_take
//   11. 空数据/大数据
//   12. 序列化异常处理
//   13. 移动语义
//   14. 重复 tensor_id 覆盖

#include "linoh/multimodal/tensor_pipeline.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh::multimodal;

// ===== 辅助函数 =====

static std::vector<std::uint8_t> make_data(std::size_t n, std::uint8_t fill = 0xAB) {
    return std::vector<std::uint8_t>(n, fill);
}

static void wait_for_ready(TensorPipeline &tp, TensorPipeline::TensorId id,
                           int max_wait_ms = 2000) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(max_wait_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (tp.try_take(id).has_value()) return;
        // try_take 会消费数据，所以只在 has_value 时返回
        // 这里改为轮询 ready_count 或直接重试
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// 尝试取，如果未就绪则等待
static std::optional<TensorPipeline::SerializedTensor> wait_and_take(
    TensorPipeline &tp, TensorPipeline::TensorId id, int max_wait_ms = 2000) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(max_wait_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        auto result = tp.try_take(id);
        if (result.has_value()) return result;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return std::nullopt;
}

// ===== 测试用例 =====

// 1. 基本 submit→try_take 流程
static void test_basic_submit_take() {
    TensorPipeline tp;
    auto data = make_data(100, 0x01);
    tp.submit(42, data);

    auto result = wait_and_take(tp, 42);
    assert(result.has_value());
    assert(result->id == 42);
    assert(result->data == data);
    printf("  [PASS] test_basic_submit_take\n");
}

// 2. try_take 未就绪返回 nullopt
static void test_try_take_not_ready() {
    TensorPipeline tp;
    tp.submit(1, make_data(50));

    // 立即 try_take，大概率未就绪
    auto result = tp.try_take(1);
    // 可能正好就绪，也可能未就绪，两种都可接受
    // 但用一个不存在的 id 一定返回 nullopt
    auto result2 = tp.try_take(999);
    assert(!result2.has_value());

    // 等待排空
    wait_and_take(tp, 1);
    printf("  [PASS] test_try_take_not_ready\n");
}

// 3. submit 非阻塞（快速返回）
static void test_submit_nonblocking() {
    TensorPipeline tp;
    auto big_data = make_data(1024 * 1024);  // 1MB

    auto start = std::chrono::steady_clock::now();
    tp.submit(1, big_data);
    auto end = std::chrono::steady_clock::now();

    auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                          end - start)
                          .count();
    // submit 应在 10ms 内返回（投递到队列，不做序列化）
    assert(elapsed_us < 10000);

    wait_and_take(tp, 1);
    printf("  [PASS] test_submit_nonblocking (elapsed=%lldus)\n", (long long)elapsed_us);
}

// 4. 乱序提交、乱序取走
static void test_out_of_order() {
    TensorPipeline tp;

    // 乱序提交：3, 1, 2
    tp.submit(3, make_data(30, 0x03));
    tp.submit(1, make_data(10, 0x01));
    tp.submit(2, make_data(20, 0x02));

    // 等待全部就绪
    auto r1 = wait_and_take(tp, 1);
    auto r2 = wait_and_take(tp, 2);
    auto r3 = wait_and_take(tp, 3);

    assert(r1.has_value() && r1->id == 1 && r1->data[0] == 0x01);
    assert(r2.has_value() && r2->id == 2 && r2->data[0] == 0x02);
    assert(r3.has_value() && r3->id == 3 && r3->data[0] == 0x03);
    printf("  [PASS] test_out_of_order\n");
}

// 5. 自定义序列化函数
static void test_custom_serialize_fn() {
    TensorPipeline tp;
    // 自定义序列化：在数据前面加 4 字节 header（magic + id）
    tp.set_serialize_fn([](TensorPipeline::TensorId id,
                           std::vector<std::uint8_t> raw) {
        std::vector<std::uint8_t> out;
        out.reserve(4 + raw.size());
        out.push_back(0xDE);
        out.push_back(0xAD);
        out.push_back(static_cast<std::uint8_t>(id & 0xFF));
        out.push_back(0x00);
        out.insert(out.end(), raw.begin(), raw.end());
        return out;
    });

    auto data = make_data(50, 0x42);
    tp.submit(7, data);

    auto result = wait_and_take(tp, 7);
    assert(result.has_value());
    assert(result->data.size() == 54);  // 4 header + 50 data
    assert(result->data[0] == 0xDE);
    assert(result->data[1] == 0xAD);
    assert(result->data[2] == 0x07);  // id & 0xFF
    assert(result->data[4] == 0x42);  // original data
    printf("  [PASS] test_custom_serialize_fn\n");
}

// 6. shutdown 后 submit 静默丢弃
static void test_submit_after_shutdown() {
    TensorPipeline tp;
    tp.shutdown();

    tp.submit(1, make_data(100));

    // 等一小段时间确认不会被处理
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(tp.ready_count() == 0);
    assert(!tp.is_running());
    assert(tp.is_shutdown());
    printf("  [PASS] test_submit_after_shutdown\n");
}

// 7. shutdown 排空队列
static void test_shutdown_drains_queue() {
    TensorPipeline tp;

    // 提交多个 tensor
    for (int i = 0; i < 10; ++i) {
        tp.submit(i, make_data(100, static_cast<std::uint8_t>(i)));
    }
    assert(tp.pending_count() > 0 || tp.ready_count() > 0);

    // shutdown 应等待队列排空
    tp.shutdown();

    // shutdown 后所有数据应已序列化到 cache
    assert(tp.pending_count() == 0);
    // ready_count 可能有数据（未被 try_take 取走）
    // 验证数据可取
    int ready = 0;
    for (int i = 0; i < 10; ++i) {
        if (tp.try_take(i).has_value()) {
            ++ready;
        }
    }
    assert(ready == 10);  // 全部就绪
    printf("  [PASS] test_shutdown_drains_queue\n");
}

// 8. pending_count / ready_count 查询
static void test_count_queries() {
    TensorPipeline tp;
    assert(tp.pending_count() == 0);
    assert(tp.ready_count() == 0);

    tp.submit(1, make_data(100));
    tp.submit(2, make_data(100));

    // 等待序列化完成
    wait_and_take(tp, 1);
    wait_and_take(tp, 2);

    assert(tp.pending_count() == 0);
    assert(tp.ready_count() == 0);  // 都被 try_take 取走了
    printf("  [PASS] test_count_queries\n");
}

// 9. 序列化不阻塞推理线程（时间验证）
static void test_no_block_inference() {
    TensorPipeline tp;
    // 设置慢序列化函数（模拟 50ms 序列化耗时）
    tp.set_serialize_fn([](TensorPipeline::TensorId,
                           std::vector<std::uint8_t> raw) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return raw;
    });

    // submit 应不被慢序列化阻塞
    auto start = std::chrono::steady_clock::now();
    tp.submit(1, make_data(100));
    tp.submit(2, make_data(100));
    tp.submit(3, make_data(100));
    auto end = std::chrono::steady_clock::now();

    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          end - start)
                          .count();
    // 3 次 submit 应在 10ms 内完成（不等待 3×50ms=150ms 序列化）
    assert(elapsed_ms < 30);

    // 等待全部完成
    wait_and_take(tp, 1);
    wait_and_take(tp, 2);
    wait_and_take(tp, 3);
    printf("  [PASS] test_no_block_inference (3 submits=%lldms, serial would be 150ms)\n",
           (long long)elapsed_ms);
}

// 10. 多线程并发 submit + try_take
static void test_multithreaded() {
    TensorPipeline tp;
    constexpr int N = 100;
    std::atomic<int> submitted{0};
    std::atomic<int> taken{0};

    // 生产者线程：submit
    std::thread producer([&] {
        for (int i = 0; i < N; ++i) {
            tp.submit(i, make_data(50, static_cast<std::uint8_t>(i)));
            submitted.fetch_add(1);
        }
    });

    // 消费者线程：try_take
    std::thread consumer([&] {
        int got = 0;
        while (got < N) {
            for (int i = 0; i < N; ++i) {
                auto r = tp.try_take(static_cast<TensorPipeline::TensorId>(i));
                if (r.has_value()) {
                    ++got;
                    ++taken;
                }
            }
            if (got < N) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    });

    producer.join();
    consumer.join();

    assert(submitted.load() == N);
    assert(taken.load() == N);
    printf("  [PASS] test_multithreaded (%d submit + %d take)\n", N, N);
}

// 11. 空数据 submit
static void test_empty_data() {
    TensorPipeline tp;
    tp.submit(1, {});

    auto result = wait_and_take(tp, 1);
    assert(result.has_value());
    assert(result->data.empty());
    printf("  [PASS] test_empty_data\n");
}

// 12. 大数据 submit（1MB）
static void test_large_data() {
    TensorPipeline tp;
    constexpr std::size_t SIZE = 1024 * 1024;  // 1MB
    auto big_data = make_data(SIZE, 0xFF);
    tp.submit(1, big_data);

    auto result = wait_and_take(tp, 1);
    assert(result.has_value());
    assert(result->data.size() == SIZE);
    assert(result->data[0] == 0xFF);
    assert(result->data[SIZE - 1] == 0xFF);
    printf("  [PASS] test_large_data (1MB)\n");
}

// 13. 序列化异常处理（不崩溃）
static void test_serialize_exception() {
    TensorPipeline tp;
    tp.set_serialize_fn([](TensorPipeline::TensorId,
                           std::vector<std::uint8_t>) -> std::vector<std::uint8_t> {
        throw std::runtime_error("serialize failed");
    });

    tp.submit(1, make_data(100));

    // 异常不应导致崩溃，应用空数据兜底
    auto result = wait_and_take(tp, 1);
    assert(result.has_value());
    assert(result->data.empty());  // 异常时返回空数据
    printf("  [PASS] test_serialize_exception\n");
}

// 14. unique_ptr 所有权转移（替代移动语义）
static void test_unique_ptr_ownership() {
    std::unique_ptr<TensorPipeline> tp1 = std::make_unique<TensorPipeline>();
    tp1->submit(1, make_data(100, 0x55));

    // 转移所有权
    std::unique_ptr<TensorPipeline> tp2 = std::move(tp1);
    assert(tp1 == nullptr);
    assert(tp2 != nullptr);

    // tp2 应能取到数据（序列化线程仍在 tp2 指向的对象中运行）
    auto result = wait_and_take(*tp2, 1);
    assert(result.has_value());
    assert(result->data[0] == 0x55);
    printf("  [PASS] test_unique_ptr_ownership\n");
}

// 15. 重复 tensor_id 覆盖
static void test_duplicate_id() {
    TensorPipeline tp;
    tp.submit(1, make_data(100, 0xAA));

    // 等第一次完成
    wait_and_take(tp, 1);

    // 用相同 id 再提交
    tp.submit(1, make_data(200, 0xBB));
    auto result = wait_and_take(tp, 1);
    assert(result.has_value());
    assert(result->data.size() == 200);
    assert(result->data[0] == 0xBB);
    printf("  [PASS] test_duplicate_id\n");
}

// 16. set_serialize_fn 设为 nullptr 回退到 identity
static void test_null_serialize_fn() {
    TensorPipeline tp;
    tp.set_serialize_fn(nullptr);  // 回退到 default_serialize (identity)

    auto data = make_data(100, 0x33);
    tp.submit(1, data);

    auto result = wait_and_take(tp, 1);
    assert(result.has_value());
    assert(result->data == data);  // identity 直接传递
    printf("  [PASS] test_null_serialize_fn\n");
}

// 17. 析构自动 shutdown
static void test_destructor_shutdown() {
    std::unique_ptr<TensorPipeline> tp = std::make_unique<TensorPipeline>();
    tp->submit(1, make_data(100));
    tp->submit(2, make_data(100));

    // 析构应自动 shutdown，不崩溃、不死锁
    tp.reset();
    // 如果到这里没死锁，测试通过
    printf("  [PASS] test_destructor_shutdown\n");
}

// 18. 流水线吞吐量 ≥ 同步序列化吞吐量
static void test_throughput() {
    constexpr int N = 20;
    constexpr std::size_t DATA_SIZE = 10000;

    // 慢序列化函数（每次 1ms，模拟真实序列化开销）
    auto slow_serialize = [](TensorPipeline::TensorId,
                             std::vector<std::uint8_t> raw) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return raw;
    };

    // 同步序列化基线：N × 1ms = 20ms
    auto sync_start = std::chrono::steady_clock::now();
    for (int i = 0; i < N; ++i) {
        auto data = make_data(DATA_SIZE, static_cast<std::uint8_t>(i));
        auto serialized = slow_serialize(i, std::move(data));
        (void)serialized;
    }
    auto sync_end = std::chrono::steady_clock::now();
    auto sync_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       sync_end - sync_start)
                       .count();

    // 异步流水线：submit 非阻塞，序列化在后台
    TensorPipeline tp;
    tp.set_serialize_fn(slow_serialize);
    auto async_start = std::chrono::steady_clock::now();
    for (int i = 0; i < N; ++i) {
        tp.submit(i, make_data(DATA_SIZE, static_cast<std::uint8_t>(i)));
    }
    auto async_end = std::chrono::steady_clock::now();
    auto async_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        async_end - async_start)
                        .count();

    // 异步 submit 应远快于同步（N×1ms vs submit 开销）
    assert(async_ms < sync_ms);

    // 排空
    for (int i = 0; i < N; ++i) {
        wait_and_take(tp, i);
    }
    printf("  [PASS] test_throughput (async=%lldms < sync=%lldms)\n",
           (long long)async_ms, (long long)sync_ms);
}

// ===== main =====

int main() {
    printf("=== v3.9.2 TensorPipeline 异步序列化流水线测试 ===\n\n");

    test_basic_submit_take();
    test_try_take_not_ready();
    test_submit_nonblocking();
    test_out_of_order();
    test_custom_serialize_fn();
    test_submit_after_shutdown();
    test_shutdown_drains_queue();
    test_count_queries();
    test_no_block_inference();
    test_multithreaded();
    test_empty_data();
    test_large_data();
    test_serialize_exception();
    test_unique_ptr_ownership();
    test_duplicate_id();
    test_null_serialize_fn();
    test_destructor_shutdown();
    test_throughput();

    printf("\n=== All 18 tests PASSED ===\n");
    return 0;
}
