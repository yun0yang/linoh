// test_bf16_transport.cpp — v3.9.4 bf16 hidden_state 透明传输测试
//
// 覆盖场景（22 个）：
//
//   bf16 转换核心（8 个）：
//   1. 零值转换 (0.0, -0.0)
//   2. 单位值转换 (1.0, -1.0, 0.5)
//   3. π 和无理数精度
//   4. 大数和小数（1e30, 1e-30）
//   5. Inf 正负无穷
//   6. NaN 传播（确保不变成 Inf）
//   7. round-to-nearest-even 舍入正确性
//   8. fp32 → bf16 → fp32 往返精度（LLM 激活值范围）
//
//   批量转换（4 个）：
//   9. 批量转换正确性（100 个确定性值）
//   10. 小端序字节布局
//   11. 缓冲区不足返回 0
//   12. vector 便利接口往返 + 奇数字节抛异常
//
//   HiddenStateCodec 透明传输（5 个）：
//   13. encode F32 零拷贝（字节流 == fp32 内存）
//   14. encode BF16 节省 50% 带宽
//   15. decode F32 还原正确
//   16. decode BF16 还原正确
//   17. encode → decode 往返（F32 + BF16 双模式）
//
//   端到端集成（5 个）：
//   18. HiddenStateCodec + TensorStreamer BF16 端到端传输
//   19. F32 向后兼容（与 v3.8.6 行为一致）
//   20. 大 tensor 多分片 BF16 传输（1000 元素，64B/分片）
//   21. estimate_bytes 和 bandwidth_saving 正确性
//   22. 不支持的 dtype 编码返回空

#include "linoh/multimodal/bf16.hpp"
#include "linoh/multimodal/hidden_state_codec.hpp"
#include "linoh/multimodal/tensor_stream.hpp"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <limits>
#include <vector>

using namespace linoh::multimodal;

// ===== 辅助函数 =====

// 确定性伪随机数生成（不依赖 rand()，跨平台一致）
static float deterministic_float(std::size_t i) {
    // 简单的 LCG 生成 [-10, 10] 范围的 float（LLM 激活值典型范围）
    std::uint64_t state = (static_cast<std::uint64_t>(i) + 1) * 6364136223846793005ULL;
    state ^= state >> 13;
    state *= 1442695040888963407ULL;
    state ^= state >> 16;
    // 映射到 [-10, 10]
    double normalized = static_cast<double>(state & 0xFFFFFF) / static_cast<double>(0xFFFFFF);
    return static_cast<float>(normalized * 20.0 - 10.0);
}

static bool float_approx(float a, float b, float rel_eps = 1e-2f) {
    if (std::isnan(a) && std::isnan(b)) return true;
    if (std::isinf(a) && std::isinf(b)) return (a > 0) == (b > 0);
    float diff = std::abs(a - b);
    float mag = std::max(std::abs(a), std::abs(b));
    if (mag < 1e-38f) return diff < 1e-38f;
    return diff / mag < rel_eps;
}

// ===== bf16 转换核心测试 =====

// 1. 零值转换
static void test_zero_conversion() {
    assert(fp32_to_bf16(0.0f) == 0x0000);
    assert(bf16_to_fp32(0x0000) == 0.0f);

    // -0.0: 符号位为 1，其余为 0
    bf16_bits_t neg_zero = fp32_to_bf16(-0.0f);
    assert(neg_zero == 0x8000);
    float restored = bf16_to_fp32(neg_zero);
    assert(std::signbit(restored));
    assert(restored == 0.0f);
    printf("  [PASS] test_zero_conversion\n");
}

// 2. 单位值转换
static void test_unit_values() {
    assert(fp32_to_bf16(1.0f) == 0x3F80);
    assert(float_approx(bf16_to_fp32(0x3F80), 1.0f));

    assert(fp32_to_bf16(-1.0f) == 0xBF80);
    assert(float_approx(bf16_to_fp32(0xBF80), -1.0f));

    // 0.5 = 2^-1，exponent=0x7E, mantissa=0
    assert(fp32_to_bf16(0.5f) == 0x3F00);
    assert(float_approx(bf16_to_fp32(0x3F00), 0.5f));
    printf("  [PASS] test_unit_values\n");
}

// 3. π 和无理数精度
static void test_pi_precision() {
    const float pi = 3.14159265f;
    bf16_bits_t bf16_pi = fp32_to_bf16(pi);
    float restored = bf16_to_fp32(bf16_pi);

    // bf16 mantissa 7 位，π 的相对误差应 < 2^-8 ≈ 0.4%
    assert(float_approx(restored, pi, 1e-2f));
    float rel_err = std::abs(restored - pi) / pi;
    assert(rel_err < 0.01f);
    printf("  [PASS] test_pi_precision (pi=%.6f bf16=%.6f rel_err=%.4f%%)\n",
           pi, restored, rel_err * 100);
}

// 4. 大数和小数
static void test_large_small_values() {
    // 1e30: 在 fp32 范围内，bf16 指数范围相同（8 位指数），应能表示
    const float large = 1e30f;
    bf16_bits_t bl = fp32_to_bf16(large);
    float rl = bf16_to_fp32(bl);
    assert(float_approx(rl, large, 1e-2f));

    // 1e-30: 同样在 bf16 指数范围内（非 denormal）
    const float small = 1e-30f;
    bf16_bits_t bs = fp32_to_bf16(small);
    float rs = bf16_to_fp32(bs);
    assert(float_approx(rs, small, 1e-2f));
    printf("  [PASS] test_large_small_values (1e30 rel_err=%.4f%%, 1e-30 rel_err=%.4f%%)\n",
           std::abs(rl - large) / large * 100,
           std::abs(rs - small) / small * 100);
}

// 5. Inf 正负无穷
static void test_infinity() {
    const float pos_inf = std::numeric_limits<float>::infinity();
    bf16_bits_t b = fp32_to_bf16(pos_inf);
    // bf16 Inf: exponent=0xFF, mantissa=0 → 0x7F80
    assert(b == 0x7F80);
    float restored = bf16_to_fp32(b);
    assert(std::isinf(restored));
    assert(restored > 0);

    const float neg_inf = -std::numeric_limits<float>::infinity();
    b = fp32_to_bf16(neg_inf);
    assert(b == 0xFF80);
    restored = bf16_to_fp32(b);
    assert(std::isinf(restored));
    assert(restored < 0);
    printf("  [PASS] test_infinity\n");
}

// 6. NaN 传播
static void test_nan_propagation() {
    // 构造一个 fp32 NaN，其 mantissa 高 7 位全 0（截断后会变 Inf 的边界情况）
    // fp32 NaN: exponent=0xFF, mantissa!=0
    // 选 mantissa = 0x1（最低位），高 7 位全 0
    std::uint32_t nan_bits = 0x7F800001;
    float nan_val;
    std::memcpy(&nan_val, &nan_bits, sizeof(nan_val));
    assert(std::isnan(nan_val));

    bf16_bits_t b = fp32_to_bf16_bits(nan_bits);
    // 转 bf16 后必须仍是 NaN（exponent=0xFF, mantissa!=0）
    std::uint16_t bf16_exp = (b >> 7) & 0xFF;
    std::uint16_t bf16_mant = b & 0x7F;
    assert(bf16_exp == 0xFF);
    assert(bf16_mant != 0);  // 关键：不能变 Inf

    float restored = bf16_to_fp32(b);
    assert(std::isnan(restored));
    printf("  [PASS] test_nan_propagation (bf16=0x%04X mantissa=0x%02X)\n", b, bf16_mant);
}

// 7. round-to-nearest-even 舍入正确性
static void test_round_to_nearest_even() {
    // bf16 mantissa 在低 7 位（bit 0..6）。round-to-nearest-even 规则：
    //   截断位 > 0.5 ULP → 向上；< 0.5 ULP → 向下；== 0.5 ULP → 向偶数（看 mantissa 最低位）

    // case A: 1.0 (bf16=0x3F80, mantissa=0 偶数) + 0.5 ULP → 向下（保持偶数）
    {
        std::uint32_t bits = 0x3F808000;  // bf16_high=0x3F80, truncated=0x8000
        bf16_bits_t b = fp32_to_bf16_bits(bits);
        assert(b == 0x3F80);  // 偶数 + 0.5 ULP → 向下
    }
    // case B: 1.0 + 0.5 ULP + 微小增量 → > 0.5 ULP → 向上
    {
        std::uint32_t bits = 0x3F808080;  // truncated=0x8080 > 0x8000
        bf16_bits_t b = fp32_to_bf16_bits(bits);
        assert(b == 0x3F81);  // > 0.5 ULP → 向上
    }
    // case C: bf16=0x3F81 (mantissa=1 奇数) + 0.5 ULP → 向上（变成偶数 0x3F82）
    {
        std::uint32_t bits = 0x3F818000;  // bf16_high=0x3F81 (奇数), truncated=0x8000
        bf16_bits_t b = fp32_to_bf16_bits(bits);
        assert(b == 0x3F82);  // 奇数 + 0.5 ULP → 向上（变偶数）
    }
    // case D: bf16=0x3F82 (mantissa=2 偶数) + 0.5 ULP → 向下（保持偶数）
    {
        std::uint32_t bits = 0x3F828000;  // bf16_high=0x3F82 (偶数), truncated=0x8000
        bf16_bits_t b = fp32_to_bf16_bits(bits);
        assert(b == 0x3F82);  // 偶数 + 0.5 ULP → 向下
    }
    printf("  [PASS] test_round_to_nearest_even\n");
}

// 8. fp32 → bf16 → fp32 往返精度（LLM 激活值范围）
static void test_roundtrip_precision() {
    // 测试 1000 个 [-10, 10] 范围的值（LLM 激活值典型范围）
    std::size_t violations = 0;
    float max_rel_err = 0.0f;
    for (std::size_t i = 0; i < 1000; ++i) {
        float original = deterministic_float(i);
        bf16_bits_t b = fp32_to_bf16(original);
        float restored = bf16_to_fp32(b);

        float rel_err = std::abs(restored - original) / std::max(std::abs(original), 1e-10f);
        if (rel_err > bf16_max_relative_error() * 2) {  // 允许 2x 理论上界
            ++violations;
        }
        max_rel_err = std::max(max_rel_err, rel_err);
    }
    assert(violations == 0);
    assert(max_rel_err < 0.01f);  // 所有值相对误差 < 1%
    printf("  [PASS] test_roundtrip_precision (1000 values, max_rel_err=%.4f%%)\n",
           max_rel_err * 100);
}

// ===== 批量转换测试 =====

// 9. 批量转换正确性
static void test_batch_conversion() {
    constexpr std::size_t N = 100;
    std::vector<float> src(N);
    for (std::size_t i = 0; i < N; ++i) {
        src[i] = deterministic_float(i);
    }

    std::vector<std::uint8_t> bytes(bf16_bytes(N));
    std::size_t written = fp32_array_to_bf16_bytes(src.data(), N, std::span<std::uint8_t>(bytes));
    assert(written == bf16_bytes(N));

    std::vector<float> restored(N);
    std::size_t read = bf16_bytes_to_fp32_array(bytes.data(), N, std::span<float>(restored));
    assert(read == bf16_bytes(N));

    for (std::size_t i = 0; i < N; ++i) {
        assert(float_approx(restored[i], src[i], 1e-2f));
    }
    printf("  [PASS] test_batch_conversion (N=%zu)\n", N);
}

// 10. 小端序字节布局
static void test_little_endian_layout() {
    // 1.0f = 0x3F800000 → bf16 = 0x3F80
    // 小端序：低字节 0x80 在前，高字节 0x3F 在后
    float val = 1.0f;
    std::vector<std::uint8_t> bytes(2);
    fp32_array_to_bf16_bytes(&val, 1, std::span<std::uint8_t>(bytes));
    assert(bytes[0] == 0x80);  // 低字节
    assert(bytes[1] == 0x3F);  // 高字节

    // 反向解析
    float restored;
    bf16_bytes_to_fp32_array(bytes.data(), 1, std::span<float>(&restored, 1));
    assert(float_approx(restored, 1.0f));
    printf("  [PASS] test_little_endian_layout\n");
}

// 11. 缓冲区不足返回 0
static void test_buffer_too_small() {
    float src[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    std::vector<std::uint8_t> small_buf(4);  // 只够 2 个 bf16，但传 4 个

    std::size_t written = fp32_array_to_bf16_bytes(src, 4, std::span<std::uint8_t>(small_buf));
    assert(written == 0);  // 缓冲区不足，返回 0

    // 输出数组过小
    float out[2];
    std::vector<std::uint8_t> bf16_data(8);  // 4 个 bf16
    fp32_array_to_bf16_bytes(src, 4, std::span<std::uint8_t>(bf16_data));
    std::size_t read = bf16_bytes_to_fp32_array(bf16_data.data(), 4, std::span<float>(out, 2));
    assert(read == 0);  // 输出缓冲区不足
    printf("  [PASS] test_buffer_too_small\n");
}

// 12. vector 便利接口往返 + 奇数字节抛异常
static void test_vector_helpers() {
    std::vector<float> src = {1.0f, -2.5f, 3.14f, -0.001f, 100.0f};
    auto bytes = fp32_vec_to_bf16_bytes(src);
    assert(bytes.size() == src.size() * 2);

    auto restored = bf16_bytes_to_fp32_vec(bytes);
    assert(restored.size() == src.size());
    for (std::size_t i = 0; i < src.size(); ++i) {
        assert(float_approx(restored[i], src[i], 1e-2f));
    }

    // 奇数字节数应抛异常
    std::vector<std::uint8_t> odd = {0x80, 0x3F, 0x00};  // 3 字节
    bool threw = false;
    try {
        bf16_bytes_to_fp32_vec(odd);
    } catch (const std::runtime_error &) {
        threw = true;
    }
    assert(threw);
    printf("  [PASS] test_vector_helpers\n");
}

// ===== HiddenStateCodec 透明传输测试 =====

// 13. encode F32 零拷贝
static void test_encode_f32_zero_copy() {
    std::vector<float> src = {1.0f, 2.0f, 3.0f, 4.0f};
    auto bytes = HiddenStateCodec::encode(src, TensorDType::F32);

    assert(bytes.size() == src.size() * 4);
    // F32 编码应直接拷贝内存（字节序与平台一致）
    float decoded;
    std::memcpy(&decoded, bytes.data() + 8, sizeof(float));  // 第 3 个元素
    assert(decoded == 3.0f);
    printf("  [PASS] test_encode_f32_zero_copy\n");
}

// 14. encode BF16 节省 50% 带宽
static void test_encode_bf16_saves_bandwidth() {
    std::vector<float> src(1000);
    for (std::size_t i = 0; i < src.size(); ++i) {
        src[i] = deterministic_float(i);
    }

    auto f32_bytes = HiddenStateCodec::encode(src, TensorDType::F32);
    auto bf16_bytes_data = HiddenStateCodec::encode(src, TensorDType::BF16);

    assert(f32_bytes.size() == 4000);
    assert(bf16_bytes_data.size() == 2000);
    assert(bf16_bytes_data.size() == f32_bytes.size() / 2);  // 节省 50%
    printf("  [PASS] test_encode_bf16_saves_bandwidth (f32=%zu bf16=%zu saved=%.0f%%)\n",
           f32_bytes.size(), bf16_bytes_data.size(),
           HiddenStateCodec::bandwidth_saving(TensorDType::BF16) * 100);
}

// 15. decode F32 还原
static void test_decode_f32() {
    std::vector<float> src = {1.5f, -2.5f, 3.14159f, -1e-10f};
    auto bytes = HiddenStateCodec::encode(src, TensorDType::F32);
    auto restored = HiddenStateCodec::decode(bytes, TensorDType::F32);

    assert(restored.size() == src.size());
    for (std::size_t i = 0; i < src.size(); ++i) {
        assert(restored[i] == src[i]);  // F32 应无损
    }
    printf("  [PASS] test_decode_f32\n");
}

// 16. decode BF16 还原
static void test_decode_bf16() {
    std::vector<float> src = {1.5f, -2.5f, 3.14159f, -1e-10f, 100.0f};
    auto bytes = HiddenStateCodec::encode(src, TensorDType::BF16);
    auto restored = HiddenStateCodec::decode(bytes, TensorDType::BF16);

    assert(restored.size() == src.size());
    for (std::size_t i = 0; i < src.size(); ++i) {
        assert(float_approx(restored[i], src[i], 1e-2f));
    }
    printf("  [PASS] test_decode_bf16\n");
}

// 17. encode → decode 往返（F32 + BF16 双模式）
static void test_encode_decode_roundtrip() {
    std::vector<float> src(500);
    for (std::size_t i = 0; i < src.size(); ++i) {
        src[i] = deterministic_float(i + 1000);
    }

    // F32 往返（无损）
    {
        auto bytes = HiddenStateCodec::encode(src, TensorDType::F32);
        auto restored = HiddenStateCodec::decode(bytes, TensorDType::F32);
        assert(restored.size() == src.size());
        for (std::size_t i = 0; i < src.size(); ++i) {
            assert(restored[i] == src[i]);
        }
    }

    // BF16 往返（有损但误差 < 1%）
    {
        auto bytes = HiddenStateCodec::encode(src, TensorDType::BF16);
        auto restored = HiddenStateCodec::decode(bytes, TensorDType::BF16);
        assert(restored.size() == src.size());
        float max_err = 0.0f;
        for (std::size_t i = 0; i < src.size(); ++i) {
            float err = std::abs(restored[i] - src[i]) / std::max(std::abs(src[i]), 1e-10f);
            max_err = std::max(max_err, err);
            assert(err < 0.01f);
        }
        (void)max_err;
    }
    printf("  [PASS] test_encode_decode_roundtrip\n");
}

// ===== 端到端集成测试 =====

// 18. HiddenStateCodec + TensorStreamer BF16 端到端传输
static void test_end_to_end_bf16_transport() {
    // 模拟 LLM hidden_state：512 维 fp32
    std::vector<float> hidden_state(512);
    for (std::size_t i = 0; i < hidden_state.size(); ++i) {
        hidden_state[i] = deterministic_float(i);
    }

    // 发送端：fp32 → bf16 编码 → TensorStreamer 分片
    auto bytes = HiddenStateCodec::encode(hidden_state, TensorDType::BF16);
    TensorStreamer streamer(64, 2);  // 64B/分片，2 stream
    auto shards = streamer.shard(42, bytes, TensorDType::BF16, {512, 0, 0, 0});

    assert(!shards.empty());
    assert(shards.front().meta.dtype == TensorDType::BF16);
    assert(shards.front().meta.shape[0] == 512);

    // 接收端：TensorReassembler 重组 → HiddenStateCodec 解码
    TensorReassembler reasm;
    std::vector<float> restored;
    reasm.on_complete([&](std::uint64_t tid, std::vector<std::uint8_t> data, TensorMeta meta) {
        assert(tid == 42);
        assert(meta.dtype == TensorDType::BF16);
        restored = HiddenStateCodec::decode(data, meta.dtype);
    });

    for (const auto &shard : shards) {
        reasm.on_shard(shard);
    }

    // 验证还原
    assert(restored.size() == hidden_state.size());
    for (std::size_t i = 0; i < hidden_state.size(); ++i) {
        assert(float_approx(restored[i], hidden_state[i], 1e-2f));
    }
    printf("  [PASS] test_end_to_end_bf16_transport (512-dim, %zu shards, bytes=%zu)\n",
           shards.size(), bytes.size());
}

// 19. F32 向后兼容（与 v3.8.6 行为一致）
static void test_f32_backward_compatibility() {
    std::vector<float> hidden_state = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};

    // 用 F32 编码（与 v3.8.6 行为一致）
    auto bytes = HiddenStateCodec::encode(hidden_state, TensorDType::F32);
    TensorStreamer streamer(16, 1);  // 16B/分片 = 4 float
    auto shards = streamer.shard(7, bytes, TensorDType::F32, {5, 0, 0, 0});

    assert(shards.front().meta.dtype == TensorDType::F32);

    TensorReassembler reasm;
    std::vector<float> restored;
    reasm.on_complete([&](std::uint64_t tid, std::vector<std::uint8_t> data, TensorMeta meta) {
        assert(tid == 7);
        assert(meta.dtype == TensorDType::F32);
        restored = HiddenStateCodec::decode(data, meta.dtype);
    });

    for (const auto &shard : shards) {
        reasm.on_shard(shard);
    }

    // F32 应无损还原
    assert(restored.size() == hidden_state.size());
    for (std::size_t i = 0; i < hidden_state.size(); ++i) {
        assert(restored[i] == hidden_state[i]);  // 完全相等
    }
    printf("  [PASS] test_f32_backward_compatibility\n");
}

// 20. 大 tensor 多分片 BF16 传输
static void test_large_tensor_bf16() {
    // 模拟大 hidden_state：10000 维 fp32（40KB），bf16 后 20KB
    std::vector<float> large(10000);
    for (std::size_t i = 0; i < large.size(); ++i) {
        large[i] = deterministic_float(i + 5000);
    }

    auto bytes = HiddenStateCodec::encode(large, TensorDType::BF16);
    assert(bytes.size() == 20000);

    // 小分片（128B = 64 个 bf16），产生多分片
    TensorStreamer streamer(128, 4);
    auto shards = streamer.shard(100, bytes, TensorDType::BF16, {10000, 0, 0, 0});

    assert(shards.size() > 10);  // 多分片
    assert(shards.back().meta.is_last);

    TensorReassembler reasm;
    std::vector<float> restored;
    reasm.on_complete([&](std::uint64_t tid, std::vector<std::uint8_t> data, TensorMeta meta) {
        assert(tid == 100);
        restored = HiddenStateCodec::decode(data, meta.dtype);
    });

    // 乱序投递部分分片（验证乱序重组）
    std::vector<std::size_t> order(shards.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
    // 简单交换前几个
    if (shards.size() > 4) {
        std::swap(order[0], order[2]);
        std::swap(order[1], order[3]);
    }
    for (std::size_t idx : order) {
        reasm.on_shard(shards[idx]);
    }

    assert(restored.size() == large.size());
    float max_err = 0;
    for (std::size_t i = 0; i < large.size(); ++i) {
        float err = std::abs(restored[i] - large[i]) / std::max(std::abs(large[i]), 1e-10f);
        max_err = std::max(max_err, err);
        assert(err < 0.01f);
    }
    printf("  [PASS] test_large_tensor_bf16 (10000-dim, %zu shards, max_err=%.4f%%)\n",
           shards.size(), max_err * 100);
}

// 21. estimate_bytes 和 bandwidth_saving 正确性
static void test_estimate_and_saving() {
    assert(HiddenStateCodec::estimate_bytes(100, TensorDType::F32) == 400);
    assert(HiddenStateCodec::estimate_bytes(100, TensorDType::BF16) == 200);
    assert(HiddenStateCodec::estimate_bytes(100, TensorDType::F16) == 200);
    assert(HiddenStateCodec::estimate_bytes(100, TensorDType::I32) == 400);
    assert(HiddenStateCodec::estimate_bytes(100, TensorDType::U8) == 100);

    assert(HiddenStateCodec::bandwidth_saving(TensorDType::F32) == 0.0);
    assert(HiddenStateCodec::bandwidth_saving(TensorDType::BF16) == 0.5);
    assert(HiddenStateCodec::bandwidth_saving(TensorDType::F16) == 0.5);
    assert(HiddenStateCodec::bandwidth_saving(TensorDType::I32) == 0.0);
    printf("  [PASS] test_estimate_and_saving\n");
}

// 22. 不支持的 dtype 编码返回空
static void test_unsupported_dtype() {
    std::vector<float> src = {1.0f, 2.0f, 3.0f};
    // F16 当前未实现转换器，应返回空
    auto bytes = HiddenStateCodec::encode(src, TensorDType::F16);
    assert(bytes.empty());

    // I32 语义不同（int32），也未实现
    bytes = HiddenStateCodec::encode(src, TensorDType::I32);
    assert(bytes.empty());

    // decode 同样返回空
    std::vector<std::uint8_t> dummy = {0, 0, 0, 0};
    auto restored = HiddenStateCodec::decode(dummy, TensorDType::F16);
    assert(restored.empty());
    printf("  [PASS] test_unsupported_dtype\n");
}

// ===== main =====

int main() {
    printf("=== v3.9.4 bf16 hidden_state 透明传输测试 ===\n\n");

    // bf16 转换核心
    test_zero_conversion();
    test_unit_values();
    test_pi_precision();
    test_large_small_values();
    test_infinity();
    test_nan_propagation();
    test_round_to_nearest_even();
    test_roundtrip_precision();

    // 批量转换
    test_batch_conversion();
    test_little_endian_layout();
    test_buffer_too_small();
    test_vector_helpers();

    // HiddenStateCodec 透明传输
    test_encode_f32_zero_copy();
    test_encode_bf16_saves_bandwidth();
    test_decode_f32();
    test_decode_bf16();
    test_encode_decode_roundtrip();

    // 端到端集成
    test_end_to_end_bf16_transport();
    test_f32_backward_compatibility();
    test_large_tensor_bf16();
    test_estimate_and_saving();
    test_unsupported_dtype();

    printf("\n=== All 22 tests PASSED ===\n");
    return 0;
}
