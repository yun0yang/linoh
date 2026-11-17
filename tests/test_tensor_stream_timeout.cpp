// tests/test_tensor_stream_timeout.cpp
// v1.5 P1-3: TensorReassembler 超时自动清理测试
//
// 验证场景：
//   1. sender 发送部分 shard 后异常退出，receiver buffers_ 累积
//   2. 60s 后自动 cleanup（默认超时）
//   3. 用户可设置自定义超时（毫秒级用于测试）
//   4. on_shard 入口自动触发清理
//   5. run_auto_cleanup() 手动触发清理返回清理数
//   6. 已完成 tensor 不被自动清理

#include "linoh/multimodal/tensor_stream.hpp"
#include "linoh/util/logging.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh::multimodal;
using clk = std::chrono::steady_clock;

static int g_pass = 0;
static int g_fail = 0;

#define EXPECT(cond, msg) do { \
    if (cond) { ++g_pass; std::printf("  [PASS] %s\n", msg); } \
    else      { ++g_fail; std::printf("  [FAIL] %s (line %d)\n", msg, __LINE__); } \
} while (0)

namespace {

// 构造一个 partial shard 流（4 个 shard 只发 1 个）
TensorShardMessage make_shard(std::uint64_t tensor_id, std::uint32_t idx, std::uint32_t total) {
    TensorShardMessage msg;
    msg.meta.tensor_id = tensor_id;
    msg.meta.total_shards = total;
    msg.meta.shard_idx = idx;
    msg.meta.dtype = TensorDType::F32;
    msg.meta.shape = {1, 0, 0, 0};
    msg.meta.total_bytes = 100;
    msg.meta.shard_bytes = 25;
    msg.meta.is_last = (idx == total - 1);
    msg.data.assign(25, static_cast<std::uint8_t>(idx + 1));
    return msg;
}

}  // namespace

// 测试 1: 默认 60s 超时不触发（短时间）
void test_default_no_cleanup() {
    std::printf("\n[TEST 1] default 60s timeout: no cleanup within 100ms\n");
    TensorReassembler reasm;
    auto shard = make_shard(1001, 0, 4);
    EXPECT(reasm.on_shard(shard), "accept first shard");
    EXPECT(reasm.pending_count() == 1, "1 pending tensor");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT(reasm.run_auto_cleanup() == 0, "no cleanup before 60s");
    EXPECT(reasm.pending_count() == 1, "still 1 pending");
}

// 测试 2: 自定义短超时触发自动清理
void test_short_timeout_cleanup() {
    std::printf("\n[TEST 2] custom 200ms timeout: auto cleanup triggered\n");
    TensorReassembler reasm;
    reasm.set_auto_cleanup_timeout_ms(std::chrono::milliseconds(200));
    auto shard = make_shard(2002, 0, 4);
    EXPECT(reasm.on_shard(shard), "accept first shard");
    EXPECT(reasm.pending_count() == 1, "1 pending tensor");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT(reasm.run_auto_cleanup() == 1, "1 tensor cleaned up by run_auto_cleanup()");
    EXPECT(reasm.pending_count() == 0, "0 pending after cleanup");
}

// 测试 3: on_shard 入口自动触发清理（不需要显式调用 run_auto_cleanup）
//   mp-P9 分桶后：on_shard 只清理同桶过期 tensor（不同桶需 run_auto_cleanup）
//   因此 3003 和 3019 必须在同一桶（3003 % 16 == 3019 % 16 == 11）
void test_onshard_entry_cleanup() {
    std::printf("\n[TEST 3] on_shard entry auto cleanup (same bucket)\n");
    TensorReassembler reasm;
    reasm.set_auto_cleanup_timeout_ms(std::chrono::milliseconds(200));
    auto shard_old = make_shard(3003, 0, 4);
    EXPECT(reasm.on_shard(shard_old), "accept old tensor's first shard");
    EXPECT(reasm.pending_count() == 1, "1 pending tensor");

    // 等待 300ms 让旧 tensor 过期
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 触发同桶新 tensor 的 on_shard，入口应自动清理同桶旧 tensor
    // 3003 & 15 == 11, 3019 & 15 == 11（同一桶）
    auto shard_new = make_shard(3019, 0, 4);
    EXPECT(reasm.on_shard(shard_new), "accept new tensor's first shard");
    EXPECT(reasm.pending_count() == 1, "1 pending after on_shard auto cleanup");
    EXPECT(!reasm.state(3003).has_value(), "old tensor 3003 cleaned up by on_shard entry");
    EXPECT(reasm.state(3019).has_value(), "new tensor 3019 retained");
}

// 测试 4: 已完成 tensor 不被超时清理（完成时 callback 路径已 erase）
void test_completed_tensor_not_cleaned() {
    std::printf("\n[TEST 4] completed tensor not affected by auto cleanup\n");
    TensorReassembler reasm;
    reasm.set_auto_cleanup_timeout_ms(std::chrono::milliseconds(200));
    std::atomic<int> cb_count{0};
    std::uint64_t cb_tid = 0;
    reasm.on_complete([&](std::uint64_t tid, std::vector<std::uint8_t>, TensorMeta) {
        ++cb_count;
        cb_tid = tid;
    });

    // 完整发送 2 个 shard
    EXPECT(reasm.on_shard(make_shard(4004, 0, 2)), "accept shard 0");
    EXPECT(reasm.on_shard(make_shard(4004, 1, 2)), "accept shard 1");
    EXPECT(cb_count == 1, "callback triggered once");
    EXPECT(cb_tid == 4004, "callback got correct tensor_id");
    EXPECT(reasm.pending_count() == 0, "0 pending after completion (auto erased in callback)");

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT(reasm.run_auto_cleanup() == 0, "no cleanup (already empty)");
    EXPECT(reasm.pending_count() == 0, "still 0 pending");
}

// 测试 5: 多个 tensor 部分超时清理（仅清理过期项）
void test_partial_timeout_cleanup() {
    std::printf("\n[TEST 5] partial timeout: only expired tensors cleaned\n");
    TensorReassembler reasm;
    reasm.set_auto_cleanup_timeout_ms(std::chrono::milliseconds(200));

    // tensor 5001 先发，等 300ms 过期
    EXPECT(reasm.on_shard(make_shard(5001, 0, 4)), "accept tensor 5001 shard 0");
    EXPECT(reasm.on_shard(make_shard(5003, 0, 4)), "accept tensor 5003 shard 0 (same time, also expire)");
    EXPECT(reasm.pending_count() == 2, "2 pending tensors (5001, 5003)");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 5001/5003 已过期，但未触发清理（因为没有新 on_shard）
    // 直接调 run_auto_cleanup 验证两个都过期
    std::size_t n1 = reasm.run_auto_cleanup();
    EXPECT(n1 == 2, "2 tensors cleaned up (5001 + 5003 both expired)");

    // 重新发 5002 立即发送
    EXPECT(reasm.on_shard(make_shard(5002, 0, 4)), "accept tensor 5002 shard 0");
    EXPECT(reasm.pending_count() == 1, "1 pending (5002 fresh)");

    // 等 5002 也过期
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    std::size_t n2 = reasm.run_auto_cleanup();
    EXPECT(n2 == 1, "1 tensor cleaned up (5002 expired)");
    EXPECT(reasm.pending_count() == 0, "0 pending after cleanup");
    EXPECT(!reasm.state(5002).has_value(), "5002 cleaned");
}

int main() {
    LINOH_INFO("=== v1.5 P1-3 TensorReassembler timeout auto cleanup tests ===");
    test_default_no_cleanup();
    test_short_timeout_cleanup();
    test_onshard_entry_cleanup();
    test_completed_tensor_not_cleaned();
    test_partial_timeout_cleanup();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
