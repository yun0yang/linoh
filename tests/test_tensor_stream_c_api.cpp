// test_tensor_stream_c_api.cpp — v5.1.0 T-LA Tensor 分片流水线 C-API 单元测试
//
// 测试覆盖：
//   1.  TensorStreamer create/free
//   2.  TensorStreamer 默认参数（shard_size=64KB, parallel_streams=4）
//   3.  TensorStreamer 自定义参数
//   4.  TensorStreamer 零大小防御（0→默认值）
//   5.  shard_count 计算（整除/非整除/0字节）
//   6.  shard 分片基本功能
//   7.  shard 分片数据正确性（拼接还原）
//   8.  shard 元数据正确性（is_last/total_shards/shard_idx）
//   9.  shards_free 内存释放（无泄漏/崩溃）
//  10.  TensorReassembler create/free
//  11.  on_complete 回调注册 + 触发
//  12.  on_shard 顺序重组
//  13.  on_shard 乱序重组
//  14.  on_shard 重复分片拒绝
//  15.  round-trip：分片→序列化→反序列化→重组 = 原数据
//  16.  progress 进度查询
//  17.  pending_count 查询
//  18.  auto_cleanup 超时清理
//  19.  dtype 传递正确性
//  20.  shape 传递正确性
//  21.  shape=NULL 默认全零
//  22.  多 tensor 并发重组
//  23.  大 tensor round-trip（1MB）
//  24.  参数校验（null 检查）
//  25.  Merkle 校验配置接口
//  26.  chunk 校验配置接口
//  27.  tensor_data_free 内存释放

#include "linoh/linoh_c.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <windows.h>  // Sleep()
#else
#include <unistd.h>   // usleep()
#endif

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL line %d: %s\n", __LINE__, #cond); } \
} while(0)

// ========== 1. TensorStreamer create/free ==========
static void test_streamer_create_free() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(1024, 2);
    CHECK(s != nullptr);
    linoh_tensor_streamer_free(s);

    // free(NULL) 安全
    linoh_tensor_streamer_free(nullptr);
}

// ========== 2. TensorStreamer 默认参数 ==========
static void test_streamer_default_params() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(0, 0);
    CHECK(s != nullptr);
    // 0 → 默认 64KB / 4
    CHECK(linoh_tensor_streamer_shard_size(s) == 64 * 1024);
    CHECK(linoh_tensor_streamer_parallel_streams(s) == 4);
    linoh_tensor_streamer_free(s);
}

// ========== 3. TensorStreamer 自定义参数 ==========
static void test_streamer_custom_params() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(4096, 8);
    CHECK(s != nullptr);
    CHECK(linoh_tensor_streamer_shard_size(s) == 4096);
    CHECK(linoh_tensor_streamer_parallel_streams(s) == 8);
    linoh_tensor_streamer_free(s);
}

// ========== 4. TensorStreamer 零大小防御 ==========
static void test_streamer_zero_defense() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(0, 0);
    CHECK(s != nullptr);
    CHECK(linoh_tensor_streamer_shard_size(s) > 0);
    CHECK(linoh_tensor_streamer_parallel_streams(s) > 0);
    linoh_tensor_streamer_free(s);
}

// ========== 5. shard_count 计算 ==========
static void test_shard_count() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(1024, 4);
    // 整除
    CHECK(linoh_tensor_streamer_shard_count(s, 4096) == 4);
    // 非整除（向上取整）
    CHECK(linoh_tensor_streamer_shard_count(s, 4097) == 5);
    // 0 字节 → 1 片
    CHECK(linoh_tensor_streamer_shard_count(s, 0) == 1);
    linoh_tensor_streamer_free(s);
}

// ========== 6. shard 分片基本功能 ==========
static void test_shard_basic() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(32, 2);
    std::vector<uint8_t> data(100);
    for (size_t i = 0; i < data.size(); ++i) data[i] = (uint8_t)(i * 3);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    int rc = linoh_tensor_streamer_shard(s, 42, data.data(), data.size(),
                                          LINOH_TENSOR_DTYPE_F32, nullptr,
                                          &shards, &count);
    CHECK(rc == LINOH_OK);
    CHECK(count == 4);  // ceil(100/32) = 4
    CHECK(shards != nullptr);

    // 每个 shard 非空（48B header + payload）
    for (size_t i = 0; i < count; ++i) {
        CHECK(shards[i].data != nullptr);
        CHECK(shards[i].len > 48);  // 至少有 header
    }

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_streamer_free(s);
}

// ========== 7. shard 分片数据正确性（拼接还原）==========
static void test_shard_data_correctness() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(50, 4);
    std::vector<uint8_t> data(125);
    for (size_t i = 0; i < data.size(); ++i) data[i] = (uint8_t)(i + 1);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    int rc = linoh_tensor_streamer_shard(s, 100, data.data(), data.size(),
                                          LINOH_TENSOR_DTYPE_F32, nullptr,
                                          &shards, &count);
    CHECK(rc == LINOH_OK);
    CHECK(count == 3);  // ceil(125/50) = 3

    // shard[0] = data[0..49], shard[1] = data[50..99], shard[2] = data[100..124]
    // 每个 shard 的 payload 跳过 48B header
    for (size_t i = 0; i < count; ++i) {
        size_t offset = i * 50;
        size_t end = (offset + 50 < data.size()) ? offset + 50 : data.size();
        size_t expected_payload = end - offset;
        size_t actual_payload = shards[i].len - 48;  // 减去 header
        CHECK(actual_payload == expected_payload);
        // 校验 payload 内容
        CHECK(std::memcmp(shards[i].data + 48, data.data() + offset, expected_payload) == 0);
    }

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_streamer_free(s);
}

// ========== 8. shard 元数据正确性 ==========
static void test_shard_meta_correctness() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(50, 4);
    std::vector<uint8_t> data(125, 0);
    uint32_t shape[4] = {1, 5, 5, 0};

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    int rc = linoh_tensor_streamer_shard(s, 600, data.data(), data.size(),
                                          LINOH_TENSOR_DTYPE_F16, shape,
                                          &shards, &count);
    CHECK(rc == LINOH_OK);
    CHECK(count == 3);

    // 验证 header 中 is_last 标记（最后一个 shard is_last=1）
    // header 布局：[0..7] tensor_id, [8..11] total_shards, [12..15] shard_idx,
    //              [16] dtype, [17..18] reserved, [19..34] shape[4],
    //              [35..42] total_bytes, [43..46] shard_bytes, [47] is_last
    for (size_t i = 0; i < count; ++i) {
        uint8_t *h = shards[i].data;
        // tensor_id (LE)
        uint64_t tid = 0;
        for (int j = 7; j >= 0; --j) tid = (tid << 8) | h[j];
        CHECK(tid == 600);

        // total_shards (LE u32)
        uint32_t ts = h[8] | (h[9] << 8) | (h[10] << 16) | (h[11] << 24);
        CHECK(ts == 3);

        // shard_idx (LE u32)
        uint32_t si = h[12] | (h[13] << 8) | (h[14] << 16) | (h[15] << 24);
        CHECK(si == i);

        // dtype
        CHECK(h[16] == (uint8_t)LINOH_TENSOR_DTYPE_F16);

        // is_last
        bool is_last = (h[47] != 0);
        CHECK(is_last == (i == count - 1));
    }

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_streamer_free(s);
}

// ========== 9. shards_free 内存释放 ==========
static void test_shards_free() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(64, 4);
    std::vector<uint8_t> data(256, 0xAB);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 1, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr,
                                 &shards, &count);
    CHECK(count == 4);
    linoh_tensor_shards_free(shards, count);

    // free(NULL, 0) 安全
    linoh_tensor_shards_free(nullptr, 0);

    linoh_tensor_streamer_free(s);
}

// ========== 10. TensorReassembler create/free ==========
static void test_reassembler_create_free() {
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();
    CHECK(r != nullptr);
    linoh_tensor_reassembler_free(r);

    // free(NULL) 安全
    linoh_tensor_reassembler_free(nullptr);
}

// ========== 11-13. on_complete + 重组（顺序/乱序/重复）==========
// 回调上下文
struct CompleteCtx {
    uint64_t tensor_id{0};
    std::vector<uint8_t> data;
    linoh_tensor_dtype_t dtype{LINOH_TENSOR_DTYPE_F32};
    uint32_t shape[4]{0, 0, 0, 0};
    uint64_t total_bytes{0};
    int call_count{0};
};

static void on_complete_cb(uint64_t tensor_id, uint8_t *data, size_t len,
                            linoh_tensor_dtype_t dtype,
                            const uint32_t shape[4],
                            uint64_t total_bytes,
                            void *user_data) {
    auto *ctx = static_cast<CompleteCtx*>(user_data);
    ctx->tensor_id = tensor_id;
    ctx->data.assign(data, data + len);
    ctx->dtype = dtype;
    if (shape) {
        for (int i = 0; i < 4; ++i) ctx->shape[i] = shape[i];
    }
    ctx->total_bytes = total_bytes;
    ctx->call_count++;
    linoh_tensor_data_free(data);
}

// ========== 11. on_complete 回调注册 + 顺序重组 ==========
static void test_reassemble_ordered() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(32, 2);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    std::vector<uint8_t> data(100);
    for (size_t i = 0; i < data.size(); ++i) data[i] = (uint8_t)(i * 2);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 300, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr,
                                 &shards, &count);
    CHECK(count == 4);

    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    // 顺序投递
    for (size_t i = 0; i < count; ++i) {
        int rc = linoh_tensor_reassembler_on_shard(r, shards[i].data, shards[i].len);
        CHECK(rc == 1);  // 新分片被接受
    }

    CHECK(ctx.call_count == 1);
    CHECK(ctx.tensor_id == 300);
    CHECK(ctx.data.size() == 100);
    CHECK(ctx.data == data);
    CHECK(ctx.total_bytes == 100);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 12. on_shard 乱序重组 ==========
static void test_reassemble_unordered() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(32, 2);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    std::vector<uint8_t> data(100);
    for (size_t i = 0; i < data.size(); ++i) data[i] = (uint8_t)(i + 5);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 301, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr,
                                 &shards, &count);
    CHECK(count == 4);

    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    // 乱序投递：3,1,0,2
    size_t order[] = {3, 1, 0, 2};
    for (size_t i = 0; i < 4; ++i) {
        int rc = linoh_tensor_reassembler_on_shard(r, shards[order[i]].data, shards[order[i]].len);
        CHECK(rc == 1);
    }

    CHECK(ctx.call_count == 1);
    CHECK(ctx.data == data);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 13. on_shard 重复分片拒绝 ==========
static void test_reassemble_duplicate() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(32, 2);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    std::vector<uint8_t> data(64, 0xCC);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 302, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr,
                                 &shards, &count);
    CHECK(count == 2);

    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    // 投递 shard 0
    int rc = linoh_tensor_reassembler_on_shard(r, shards[0].data, shards[0].len);
    CHECK(rc == 1);

    // 重复投递 shard 0 → 返回 0（拒绝）
    rc = linoh_tensor_reassembler_on_shard(r, shards[0].data, shards[0].len);
    CHECK(rc == 0);

    // 投递 shard 1 → 完成
    rc = linoh_tensor_reassembler_on_shard(r, shards[1].data, shards[1].len);
    CHECK(rc == 1);

    CHECK(ctx.call_count == 1);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 14. round-trip 数据一致性 ==========
static void test_round_trip() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(64, 4);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    // 不规则大小
    std::vector<uint8_t> data(250);
    for (size_t i = 0; i < data.size(); ++i) data[i] = (uint8_t)(i * 7 + 3);

    uint32_t shape[4] = {1, 5, 10, 5};

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 999, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F16, shape,
                                 &shards, &count);
    CHECK(count > 0);

    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    // 逐个投递
    for (size_t i = 0; i < count; ++i) {
        linoh_tensor_reassembler_on_shard(r, shards[i].data, shards[i].len);
    }

    CHECK(ctx.call_count == 1);
    CHECK(ctx.tensor_id == 999);
    CHECK(ctx.data.size() == data.size());
    CHECK(ctx.data == data);
    CHECK(ctx.dtype == LINOH_TENSOR_DTYPE_F16);
    CHECK(ctx.total_bytes == data.size());
    // shape 传递
    CHECK(ctx.shape[0] == 1);
    CHECK(ctx.shape[1] == 5);
    CHECK(ctx.shape[2] == 10);
    CHECK(ctx.shape[3] == 5);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 15. progress 进度查询 ==========
static void test_progress() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(32, 2);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    std::vector<uint8_t> data(128, 0);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 400, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr,
                                 &shards, &count);
    CHECK(count == 4);

    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    // 初始进度 0
    float p0 = linoh_tensor_reassembler_progress(r, 400);
    CHECK(p0 == 0.0f);

    // 投递 1 片 → 25%
    linoh_tensor_reassembler_on_shard(r, shards[0].data, shards[0].len);
    float p1 = linoh_tensor_reassembler_progress(r, 400);
    CHECK(p1 > 0.2f);
    CHECK(p1 < 0.3f);

    // 投递 2 片 → 50%
    linoh_tensor_reassembler_on_shard(r, shards[1].data, shards[1].len);
    float p2 = linoh_tensor_reassembler_progress(r, 400);
    CHECK(p2 >= 0.49f);
    CHECK(p2 <= 0.51f);

    // 投递 3 片 → 75%
    linoh_tensor_reassembler_on_shard(r, shards[2].data, shards[2].len);
    float p3 = linoh_tensor_reassembler_progress(r, 400);
    CHECK(p3 > 0.7f);
    CHECK(p3 < 0.8f);

    // 全部投递 → 100% + 回调触发
    linoh_tensor_reassembler_on_shard(r, shards[3].data, shards[3].len);
    CHECK(ctx.call_count == 1);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 16. pending_count 查询 ==========
static void test_pending_count() {
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();
    CHECK(linoh_tensor_reassembler_pending_count(r) == 0);

    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(32, 2);
    std::vector<uint8_t> data(64, 0);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 500, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr,
                                 &shards, &count);
    CHECK(count == 2);

    // 投递 1 片 → pending=1
    linoh_tensor_reassembler_on_shard(r, shards[0].data, shards[0].len);
    CHECK(linoh_tensor_reassembler_pending_count(r) == 1);

    // 投递 2 片 → 完成 → pending=0（回调后自动清理）
    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);
    linoh_tensor_reassembler_on_shard(r, shards[1].data, shards[1].len);
    CHECK(ctx.call_count == 1);
    CHECK(linoh_tensor_reassembler_pending_count(r) == 0);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 17. auto_cleanup 超时清理 ==========
static void test_auto_cleanup() {
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    // 设置 1 秒超时
    linoh_tensor_reassembler_set_auto_cleanup_timeout(r, 1);

    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(32, 2);
    std::vector<uint8_t> data(64, 0);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 600, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr,
                                 &shards, &count);

    // 只投递 1 片（不完整）
    linoh_tensor_reassembler_on_shard(r, shards[0].data, shards[0].len);
    CHECK(linoh_tensor_reassembler_pending_count(r) == 1);

    // 等待超时（sleep 1.2s）
#ifdef _WIN32
    Sleep(1200);
#else
    usleep(1200000);
#endif

    // 手动触发清理
    size_t cleaned = linoh_tensor_reassembler_run_auto_cleanup(r);
    CHECK(cleaned == 1);
    CHECK(linoh_tensor_reassembler_pending_count(r) == 0);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 18. dtype 传递正确性 ==========
static void test_dtype_transfer() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(64, 4);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    std::vector<uint8_t> data(64, 0);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 700, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_BF16, nullptr,
                                 &shards, &count);

    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    for (size_t i = 0; i < count; ++i) {
        linoh_tensor_reassembler_on_shard(r, shards[i].data, shards[i].len);
    }

    CHECK(ctx.dtype == LINOH_TENSOR_DTYPE_BF16);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 19. shape 传递正确性 ==========
static void test_shape_transfer() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(64, 4);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    std::vector<uint8_t> data(64, 0);
    uint32_t shape[4] = {2, 4, 8, 0};

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 701, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F32, shape,
                                 &shards, &count);

    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    for (size_t i = 0; i < count; ++i) {
        linoh_tensor_reassembler_on_shard(r, shards[i].data, shards[i].len);
    }

    CHECK(ctx.shape[0] == 2);
    CHECK(ctx.shape[1] == 4);
    CHECK(ctx.shape[2] == 8);
    CHECK(ctx.shape[3] == 0);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 20. shape=NULL 默认全零 ==========
static void test_shape_null() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(64, 4);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    std::vector<uint8_t> data(64, 0);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    // shape=NULL → 默认全零
    linoh_tensor_streamer_shard(s, 702, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr,
                                 &shards, &count);

    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    for (size_t i = 0; i < count; ++i) {
        linoh_tensor_reassembler_on_shard(r, shards[i].data, shards[i].len);
    }

    CHECK(ctx.shape[0] == 0);
    CHECK(ctx.shape[1] == 0);
    CHECK(ctx.shape[2] == 0);
    CHECK(ctx.shape[3] == 0);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 21. 多 tensor 并发重组 ==========
static void test_multi_tensor() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(32, 4);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    std::vector<uint8_t> data1(64), data2(96);
    for (size_t i = 0; i < data1.size(); ++i) data1[i] = (uint8_t)i;
    for (size_t i = 0; i < data2.size(); ++i) data2[i] = (uint8_t)(i + 100);

    linoh_tensor_shard_t *shards1 = nullptr, *shards2 = nullptr;
    size_t count1 = 0, count2 = 0;
    linoh_tensor_streamer_shard(s, 800, data1.data(), data1.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr, &shards1, &count1);
    linoh_tensor_streamer_shard(s, 801, data2.data(), data2.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr, &shards2, &count2);

    CompleteCtx ctx;  // 两个 tensor 共用一个回调上下文
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    // 交替投递
    linoh_tensor_reassembler_on_shard(r, shards1[0].data, shards1[0].len);
    linoh_tensor_reassembler_on_shard(r, shards2[0].data, shards2[0].len);
    linoh_tensor_reassembler_on_shard(r, shards1[1].data, shards1[1].len);
    // tensor 800 完成
    CHECK(ctx.call_count == 1);
    CHECK(ctx.tensor_id == 800);
    CHECK(ctx.data == data1);

    linoh_tensor_reassembler_on_shard(r, shards2[1].data, shards2[1].len);
    linoh_tensor_reassembler_on_shard(r, shards2[2].data, shards2[2].len);
    // tensor 801 完成
    CHECK(ctx.call_count == 2);

    linoh_tensor_shards_free(shards1, count1);
    linoh_tensor_shards_free(shards2, count2);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 22. 大 tensor round-trip（1MB）==========
static void test_large_tensor_1mb() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(64 * 1024, 4);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    const size_t SIZE = 1024 * 1024;  // 1MB
    std::vector<uint8_t> data(SIZE);
    for (size_t i = 0; i < SIZE; ++i) data[i] = (uint8_t)(i & 0xFF);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    linoh_tensor_streamer_shard(s, 900, data.data(), data.size(),
                                 LINOH_TENSOR_DTYPE_F32, nullptr,
                                 &shards, &count);
    CHECK(count == 16);  // 1MB / 64KB = 16

    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    for (size_t i = 0; i < count; ++i) {
        linoh_tensor_reassembler_on_shard(r, shards[i].data, shards[i].len);
    }

    CHECK(ctx.call_count == 1);
    CHECK(ctx.data.size() == SIZE);
    CHECK(ctx.data == data);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

// ========== 23. 参数校验（null 检查）==========
static void test_null_checks() {
    // streamer null
    CHECK(linoh_tensor_streamer_shard_size(nullptr) == 0);
    CHECK(linoh_tensor_streamer_parallel_streams(nullptr) == 0);
    CHECK(linoh_tensor_streamer_shard_count(nullptr, 100) == 0);

    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    CHECK(linoh_tensor_streamer_shard(nullptr, 1, nullptr, 0,
                                       LINOH_TENSOR_DTYPE_F32, nullptr,
                                       &shards, &count) == LINOH_ERR_PARAM);

    // reassembler null
    CHECK(linoh_tensor_reassembler_progress(nullptr, 1) == 0.0f);
    CHECK(linoh_tensor_reassembler_pending_count(nullptr) == 0);
    CHECK(linoh_tensor_reassembler_on_shard(nullptr, nullptr, 0) == LINOH_ERR_PARAM);

    // 有效 streamer 但 null 输出参数
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(64, 4);
    std::vector<uint8_t> data(64, 0);
    CHECK(linoh_tensor_streamer_shard(s, 1, data.data(), data.size(),
                                       LINOH_TENSOR_DTYPE_F32, nullptr,
                                       nullptr, &count) == LINOH_ERR_PARAM);
    CHECK(linoh_tensor_streamer_shard(s, 1, data.data(), data.size(),
                                       LINOH_TENSOR_DTYPE_F32, nullptr,
                                       &shards, nullptr) == LINOH_ERR_PARAM);
    linoh_tensor_streamer_free(s);
}

// ========== 24. Merkle 校验配置接口 ==========
static void test_merkle_config() {
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    // 默认禁用
    // 设置期望 root（全零 = 无需校验）
    uint8_t zero_root[32] = {0};
    linoh_tensor_reassembler_set_expected_merkle_root(r, 1000, zero_root);

    // 启用 Merkle 校验
    linoh_tensor_reassembler_set_verify_merkle(r, 1);
    linoh_tensor_reassembler_set_verify_merkle(r, 0);

    // 启用 chunk 校验
    linoh_tensor_reassembler_set_verify_chunk_hashes(r, 1);
    linoh_tensor_reassembler_set_verify_chunk_hashes(r, 0);

    // null 安全
    linoh_tensor_reassembler_set_expected_merkle_root(nullptr, 1000, zero_root);
    linoh_tensor_reassembler_set_verify_merkle(nullptr, 1);
    linoh_tensor_reassembler_set_verify_chunk_hashes(nullptr, 1);

    linoh_tensor_reassembler_free(r);
    CHECK(1);  // 如果到这里没崩溃就通过
}

// ========== 25. tensor_data_free 内存释放 ==========
static void test_tensor_data_free() {
    // 分配 → free
    uint8_t *p = (uint8_t*)std::malloc(100);
    CHECK(p != nullptr);
    linoh_tensor_data_free(p);

    // free(NULL) 安全
    linoh_tensor_data_free(nullptr);
}

// ========== 26. 空 tensor 分片 ==========
static void test_empty_tensor() {
    linoh_tensor_streamer_t *s = linoh_tensor_streamer_create(64, 4);
    linoh_tensor_reassembler_t *r = linoh_tensor_reassembler_create();

    // 0 字节 tensor → 1 个分片
    linoh_tensor_shard_t *shards = nullptr;
    size_t count = 0;
    int rc = linoh_tensor_streamer_shard(s, 1000, nullptr, 0,
                                          LINOH_TENSOR_DTYPE_F32, nullptr,
                                          &shards, &count);
    CHECK(rc == LINOH_OK);
    CHECK(count == 1);

    CompleteCtx ctx;
    linoh_tensor_reassembler_on_complete(r, on_complete_cb, &ctx);

    linoh_tensor_reassembler_on_shard(r, shards[0].data, shards[0].len);
    CHECK(ctx.call_count == 1);
    CHECK(ctx.data.empty() || ctx.data.size() == 0);

    linoh_tensor_shards_free(shards, count);
    linoh_tensor_reassembler_free(r);
    linoh_tensor_streamer_free(s);
}

int main() {
    test_streamer_create_free();
    test_streamer_default_params();
    test_streamer_custom_params();
    test_streamer_zero_defense();
    test_shard_count();
    test_shard_basic();
    test_shard_data_correctness();
    test_shard_meta_correctness();
    test_shards_free();
    test_reassembler_create_free();
    test_reassemble_ordered();
    test_reassemble_unordered();
    test_reassemble_duplicate();
    test_round_trip();
    test_progress();
    test_pending_count();
    test_auto_cleanup();
    test_dtype_transfer();
    test_shape_transfer();
    test_shape_null();
    test_multi_tensor();
    test_large_tensor_1mb();
    test_null_checks();
    test_merkle_config();
    test_tensor_data_free();
    test_empty_tensor();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
