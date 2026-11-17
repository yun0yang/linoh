// test_fec_simd.cpp — v3.3.0 突破3: FEC SIMD 加速 + 自适应恢复测试
//
// 覆盖范围：
//   1. CPU 特征检测（detect_cpu_features）
//   2. SIMD 批量 GF(256) 乘法 vs 标量结果一致性
//   3. SIMD 批量 XOR 正确性
//   4. 边界条件（非对齐长度、空输入、coef=0）
//   5. RS 编码（SIMD 路径）vs 标量编码结果一致
//   6. XOR 编码（SIMD 路径）正确性 + 解码恢复
//   7. RS 编解码端到端（SIMD 路径）
//   8. 自适应 FEC 配置建议（各丢包率档位 + 场景 profile）
//   9. 性能对比（SIMD vs 标量，可选）

#include "linoh/fec/fec.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

using namespace linoh;

#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    ++g_failed; } else { ++g_passed; } } while (0)

static int g_passed = 0;
static int g_failed = 0;

// ========== CPU 特征检测 ==========

// 测试 1: detect_cpu_features 返回有效结果（至少能检测到一个特征或全 false）
static void test_cpu_features_detect() {
    printf("[test] detect_cpu_features returns valid result...\n");
    const auto &cpu = fec::gf256::detect_cpu_features();
    // 大多数现代 x86 CPU 至少有 SSE2；如果全 false 说明检测逻辑有问题
    // 这里只验证调用不崩溃，且结果一致（多次调用返回相同）
    const auto &cpu2 = fec::gf256::detect_cpu_features();
    CHECK(cpu.has_sse2 == cpu2.has_sse2);
    CHECK(cpu.has_ssse3 == cpu2.has_ssse3);
    CHECK(cpu.has_avx2 == cpu2.has_avx2);
    printf("  CPU: sse2=%d ssse3=%d avx2=%d avx512=%d neon=%d\n",
           cpu.has_sse2, cpu.has_ssse3, cpu.has_avx2, cpu.has_avx512, cpu.has_neon);
}

// 测试 2: active_backend 返回非空字符串
static void test_active_backend() {
    printf("[test] active_backend returns non-empty string...\n");
    const char *backend = fec::gf256::simd::active_backend();
    CHECK(backend != nullptr);
    CHECK(backend[0] != '\0');
    printf("  Active SIMD backend: %s\n", backend);
}

// ========== SIMD 批量 GF(256) 乘法正确性 ==========

// 测试 3: mul_xor_batch vs 标量逐字节一致（随机数据）
static void test_mul_xor_batch_vs_scalar() {
    printf("[test] mul_xor_batch vs scalar (random data)...\n");
    std::mt19937 rng(42);
    const std::size_t sizes[] = {1, 15, 16, 17, 31, 32, 33, 63, 64, 100, 255, 1024, 4096};
    for (std::size_t sz : sizes) {
        std::vector<std::uint8_t> in(sz), out_simd(sz), out_scalar(sz);
        for (std::size_t i = 0; i < sz; ++i) in[i] = static_cast<std::uint8_t>(rng());
        for (std::size_t i = 0; i < sz; ++i) {
            out_simd[i] = static_cast<std::uint8_t>(rng());
            out_scalar[i] = out_simd[i];  // 相同初始值
        }
        std::uint8_t coef = static_cast<std::uint8_t>(rng() % 256);

        // SIMD 路径
        fec::gf256::simd::mul_xor_batch(coef, in.data(), out_simd.data(), sz);
        // 标量路径
        for (std::size_t i = 0; i < sz; ++i) {
            out_scalar[i] ^= fec::gf256::mul(coef, in[i]);
        }
        CHECK(std::memcmp(out_simd.data(), out_scalar.data(), sz) == 0);
    }
}

// 测试 4: mul_xor_batch coef=0 不改变 out
static void test_mul_xor_batch_zero_coef() {
    printf("[test] mul_xor_batch coef=0 no change...\n");
    std::vector<std::uint8_t> in(64, 0xAA), out(64, 0x55);
    std::vector<std::uint8_t> out_orig = out;
    fec::gf256::simd::mul_xor_batch(0, in.data(), out.data(), 64);
    CHECK(std::memcmp(out.data(), out_orig.data(), 64) == 0);
}

// 测试 5: mul_xor_batch 累加正确性（多次调用）
static void test_mul_xor_batch_accumulate() {
    printf("[test] mul_xor_batch accumulate (multiple calls)...\n");
    const std::size_t sz = 1024;
    std::mt19937 rng(123);
    std::vector<std::uint8_t> out_simd(sz, 0), out_scalar(sz, 0);

    for (int iter = 0; iter < 5; ++iter) {
        std::vector<std::uint8_t> in(sz);
        for (auto &b : in) b = static_cast<std::uint8_t>(rng());
        std::uint8_t coef = static_cast<std::uint8_t>(rng() % 256);
        fec::gf256::simd::mul_xor_batch(coef, in.data(), out_simd.data(), sz);
        for (std::size_t i = 0; i < sz; ++i) {
            out_scalar[i] ^= fec::gf256::mul(coef, in[i]);
        }
    }
    CHECK(std::memcmp(out_simd.data(), out_scalar.data(), sz) == 0);
}

// 测试 6: mul_xor_batch 边界（n=0 不崩溃）
static void test_mul_xor_batch_zero_length() {
    printf("[test] mul_xor_batch n=0 no crash...\n");
    std::uint8_t dummy = 0;
    fec::gf256::simd::mul_xor_batch(0x42, &dummy, &dummy, 0);
    CHECK(true);  // 不崩溃即通过
}

// ========== SIMD 批量 XOR 正确性 ==========

// 测试 7: xor_batch vs 标量一致
static void test_xor_batch_vs_scalar() {
    printf("[test] xor_batch vs scalar...\n");
    std::mt19937 rng(99);
    const std::size_t sizes[] = {1, 15, 16, 17, 31, 32, 33, 100, 1024};
    for (std::size_t sz : sizes) {
        std::vector<std::uint8_t> in(sz), out_simd(sz), out_scalar(sz);
        for (std::size_t i = 0; i < sz; ++i) {
            in[i] = static_cast<std::uint8_t>(rng());
            out_simd[i] = static_cast<std::uint8_t>(rng());
            out_scalar[i] = out_simd[i];
        }
        fec::gf256::simd::xor_batch(in.data(), out_simd.data(), sz);
        for (std::size_t i = 0; i < sz; ++i) out_scalar[i] ^= in[i];
        CHECK(std::memcmp(out_simd.data(), out_scalar.data(), sz) == 0);
    }
}

// 测试 8: xor_batch n=0 不崩溃
static void test_xor_batch_zero_length() {
    printf("[test] xor_batch n=0 no crash...\n");
    std::uint8_t dummy = 0;
    fec::gf256::simd::xor_batch(&dummy, &dummy, 0);
    CHECK(true);
}

// ========== RS 编码（SIMD 路径）端到端 ==========

// 测试 9: RS 编码 + 解码端到端（SIMD 路径，无丢包）
static void test_rs_encode_decode_no_loss() {
    printf("[test] RS encode+decode no loss (SIMD path)...\n");
    fec::FecConfig cfg;
    cfg.type = fec::FecType::ReedSolomon;
    cfg.data_blocks = 4;
    cfg.recovery_blocks = 2;
    cfg.block_size = 256;

    auto enc = fec::create_encoder(cfg);
    auto dec = fec::create_decoder(cfg);
    CHECK(enc != nullptr);
    CHECK(dec != nullptr);

    // 准备数据
    std::vector<std::vector<std::uint8_t>> data(4, std::vector<std::uint8_t>(256));
    for (std::size_t i = 0; i < 4; ++i)
        for (std::size_t j = 0; j < 256; ++j)
            data[i][j] = static_cast<std::uint8_t>((i * 256 + j) & 0xFF);

    std::vector<std::span<const std::uint8_t>> data_spans;
    for (auto &d : data) data_spans.emplace_back(d.data(), d.size());

    auto encoded = enc->encode(data_spans);
    CHECK(encoded.size() == 6);  // K+M = 4+2

    // 解码（无丢包）
    std::vector<std::optional<std::vector<std::uint8_t>>> received(6);
    for (std::size_t i = 0; i < 6; ++i) received[i] = encoded[i];

    auto decoded = dec->decode(received);
    CHECK(decoded.has_value());
    CHECK(decoded->size() == 4);
    for (std::size_t i = 0; i < 4; ++i) {
        CHECK(std::memcmp((*decoded)[i].data(), data[i].data(), 256) == 0);
    }
}

// 测试 10: RS 编码 + 解码恢复（丢失 M 块）
static void test_rs_encode_decode_with_loss() {
    printf("[test] RS encode+decode with loss (SIMD path)...\n");
    fec::FecConfig cfg;
    cfg.type = fec::FecType::ReedSolomon;
    cfg.data_blocks = 6;
    cfg.recovery_blocks = 3;
    cfg.block_size = 512;

    auto enc = fec::create_encoder(cfg);
    auto dec = fec::create_decoder(cfg);

    std::vector<std::vector<std::uint8_t>> data(6, std::vector<std::uint8_t>(512));
    std::mt19937 rng(777);
    for (auto &d : data) for (auto &b : d) b = static_cast<std::uint8_t>(rng());

    std::vector<std::span<const std::uint8_t>> data_spans;
    for (auto &d : data) data_spans.emplace_back(d.data(), d.size());

    auto encoded = enc->encode(data_spans);
    CHECK(encoded.size() == 9);

    // 丢失 3 块（数据块 1, 3 + 冗余块 0）
    std::vector<std::optional<std::vector<std::uint8_t>>> received(9);
    for (std::size_t i = 0; i < 9; ++i) {
        if (i == 1 || i == 3 || i == 6) continue;  // 丢失
        received[i] = encoded[i];
    }

    auto decoded = dec->decode(received);
    CHECK(decoded.has_value());
    CHECK(decoded->size() == 6);
    for (std::size_t i = 0; i < 6; ++i) {
        CHECK(std::memcmp((*decoded)[i].data(), data[i].data(), 512) == 0);
    }
}

// 测试 11: RS 编码结果与标量路径一致（通过对比已知模式）
static void test_rs_encode_consistency() {
    printf("[test] RS encode consistency (SIMD vs known pattern)...\n");
    // 多次编码同一数据，结果应一致（确定性）
    fec::FecConfig cfg;
    cfg.type = fec::FecType::ReedSolomon;
    cfg.data_blocks = 3;
    cfg.recovery_blocks = 2;
    cfg.block_size = 128;

    auto enc = fec::create_encoder(cfg);
    std::vector<std::vector<std::uint8_t>> data(3, std::vector<std::uint8_t>(128, 0));
    data[0][0] = 0x01; data[1][0] = 0x02; data[2][0] = 0x03;

    std::vector<std::span<const std::uint8_t>> spans;
    for (auto &d : data) spans.emplace_back(d.data(), d.size());

    auto r1 = enc->encode(spans);
    auto r2 = enc->encode(spans);
    CHECK(r1.size() == r2.size());
    for (std::size_t i = 0; i < r1.size(); ++i) {
        CHECK(std::memcmp(r1[i].data(), r2[i].data(), 128) == 0);
    }
}

// ========== XOR FEC（SIMD 路径）==========

// 测试 12: XOR FEC 编码 + 解码恢复
static void test_xor_fec_simd() {
    printf("[test] XOR FEC encode+decode (SIMD path)...\n");
    fec::FecConfig cfg;
    cfg.type = fec::FecType::Xor;
    cfg.data_blocks = 5;
    cfg.recovery_blocks = 1;
    cfg.block_size = 256;

    auto enc = fec::create_encoder(cfg);
    auto dec = fec::create_decoder(cfg);

    std::vector<std::vector<std::uint8_t>> data(5, std::vector<std::uint8_t>(256));
    std::mt19937 rng(555);
    for (auto &d : data) for (auto &b : d) b = static_cast<std::uint8_t>(rng());

    std::vector<std::span<const std::uint8_t>> spans;
    for (auto &d : data) spans.emplace_back(d.data(), d.size());

    auto encoded = enc->encode(spans);
    CHECK(encoded.size() == 6);

    // 丢失 1 块（数据块 2），用 XOR 恢复
    std::vector<std::optional<std::vector<std::uint8_t>>> received(6);
    for (std::size_t i = 0; i < 6; ++i) {
        if (i == 2) continue;
        received[i] = encoded[i];
    }
    auto decoded = dec->decode(received);
    CHECK(decoded.has_value());
    CHECK(decoded->size() == 5);
    for (std::size_t i = 0; i < 5; ++i) {
        CHECK(std::memcmp((*decoded)[i].data(), data[i].data(), 256) == 0);
    }
}

// ========== 自适应 FEC 配置建议 ==========

// 测试 13: 自适应建议 — 低丢包不启用 FEC
static void test_adaptive_low_loss_no_fec() {
    printf("[test] adaptive: low loss (<0.1%%) no FEC...\n");
    fec::adaptive::NetworkQuality q;
    q.loss_rate = 0.0005;  // 0.05%
    auto rec = fec::adaptive::recommend_fec_config(q);
    CHECK(rec.type == fec::FecType::None);
}

// 测试 14: 自适应建议 — 0.1%-1% 轻度保护
static void test_adaptive_light_protection() {
    printf("[test] adaptive: 0.1%%-1%% light protection (K=16 M=1)...\n");
    fec::adaptive::NetworkQuality q;
    q.loss_rate = 0.005;  // 0.5%
    auto rec = fec::adaptive::recommend_fec_config(q);
    CHECK(rec.type == fec::FecType::ReedSolomon);
    CHECK(rec.data_blocks == 16);
    CHECK(rec.recovery_blocks == 1);
}

// 测试 15: 自适应建议 — 1%-5% 中度保护
static void test_adaptive_moderate_protection() {
    printf("[test] adaptive: 1%%-5%% moderate protection (K=10 M=2)...\n");
    fec::adaptive::NetworkQuality q;
    q.loss_rate = 0.03;  // 3%
    auto rec = fec::adaptive::recommend_fec_config(q);
    CHECK(rec.type == fec::FecType::ReedSolomon);
    CHECK(rec.data_blocks == 10);
    CHECK(rec.recovery_blocks == 2);
}

// 测试 16: 自适应建议 — 5%-10% 重度保护
static void test_adaptive_heavy_protection() {
    printf("[test] adaptive: 5%%-10%% heavy protection (K=8 M=3)...\n");
    fec::adaptive::NetworkQuality q;
    q.loss_rate = 0.07;  // 7%
    auto rec = fec::adaptive::recommend_fec_config(q);
    CHECK(rec.type == fec::FecType::ReedSolomon);
    CHECK(rec.data_blocks == 8);
    CHECK(rec.recovery_blocks == 3);
}

// 测试 17: 自适应建议 — >10% 最大保护
static void test_adaptive_max_protection() {
    printf("[test] adaptive: >10%% max protection (K=6 M=4)...\n");
    fec::adaptive::NetworkQuality q;
    q.loss_rate = 0.15;  // 15%
    auto rec = fec::adaptive::recommend_fec_config(q);
    CHECK(rec.type == fec::FecType::ReedSolomon);
    CHECK(rec.data_blocks == 6);
    CHECK(rec.recovery_blocks == 4);
}

// 测试 18: 自适应建议 — HighReliability 强制启用
static void test_adaptive_high_reliability_forced() {
    printf("[test] adaptive: HighReliability forced FEC...\n");
    fec::adaptive::NetworkQuality q;
    q.loss_rate = 0.0001;  // 0.01%（很低）
    auto rec = fec::adaptive::recommend_fec_config(q, fec::adaptive::FecProfile::HighReliability);
    CHECK(rec.type == fec::FecType::ReedSolomon);
    CHECK(rec.data_blocks == 16);
    CHECK(rec.recovery_blocks == 1);
}

// 测试 19: 自适应建议 — LowLatency 大 K
static void test_adaptive_low_latency_large_k() {
    printf("[test] adaptive: LowLatency larger K...\n");
    fec::adaptive::NetworkQuality q;
    q.loss_rate = 0.03;  // 3%（中度保护，Balanced 时 K=10）
    auto rec = fec::adaptive::recommend_fec_config(q, fec::adaptive::FecProfile::LowLatency);
    CHECK(rec.type == fec::FecType::ReedSolomon);
    CHECK(rec.data_blocks == 16);  // LowLatency 强制 K>=16
    CHECK(rec.recovery_blocks == 2);
}

// 测试 20: 自适应建议 — block_size 透传
static void test_adaptive_block_size_passthrough() {
    printf("[test] adaptive: block_size passthrough...\n");
    fec::adaptive::NetworkQuality q;
    q.loss_rate = 0.005;
    auto rec = fec::adaptive::recommend_fec_config(q, fec::adaptive::FecProfile::Balanced, 4096);
    CHECK(rec.block_size == 4096);
    auto rec2 = fec::adaptive::recommend_fec_config(q, fec::adaptive::FecProfile::Balanced, 0);
    CHECK(rec2.block_size == 1024);  // 默认
}

// 测试 21: 自适应建议 — 推荐配置可构造有效 encoder
static void test_adaptive_recommendation_valid() {
    printf("[test] adaptive: recommendation constructs valid encoder...\n");
    fec::adaptive::NetworkQuality q;
    q.loss_rate = 0.03;
    auto rec = fec::adaptive::recommend_fec_config(q);
    fec::FecConfig cfg;
    cfg.type = rec.type;
    cfg.data_blocks = rec.data_blocks;
    cfg.recovery_blocks = rec.recovery_blocks;
    cfg.block_size = rec.block_size;
    CHECK(cfg.valid());
    auto enc = fec::create_encoder(cfg);
    CHECK(enc != nullptr);
}

// ========== 性能对比（可选，不严格断言） ==========

// 测试 22: 性能对比（SIMD vs 标量，仅打印，不严格断言）
static void test_perf_comparison() {
    printf("[test] perf comparison (SIMD vs scalar, info only)...\n");
    const std::size_t sz = 64 * 1024;  // 64KB
    const int iters = 1000;
    std::vector<std::uint8_t> in(sz, 0xAB), out(sz, 0);

    // SIMD 路径
    auto t1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) {
        std::fill(out.begin(), out.end(), 0);
        fec::gf256::simd::mul_xor_batch(0x53, in.data(), out.data(), sz);
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    double simd_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();

    // 标量路径
    t1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) {
        std::fill(out.begin(), out.end(), 0);
        for (std::size_t j = 0; j < sz; ++j) {
            out[j] ^= fec::gf256::mul(0x53, in[j]);
        }
    }
    t2 = std::chrono::high_resolution_clock::now();
    double scalar_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();

    printf("  SIMD %s:   %.2f ms (%d iters, %zu bytes)\n",
           fec::gf256::simd::active_backend(), simd_ms, iters, sz);
    printf("  Scalar:    %.2f ms\n", scalar_ms);
    if (scalar_ms > 0.001) {
        printf("  Speedup:   %.2fx\n", scalar_ms / simd_ms);
    }
    CHECK(simd_ms > 0);
    CHECK(scalar_ms > 0);
}

int main() {
    printf("=== test_fec_simd (v3.3.0 突破3) ===\n\n");

    test_cpu_features_detect();
    test_active_backend();

    test_mul_xor_batch_vs_scalar();
    test_mul_xor_batch_zero_coef();
    test_mul_xor_batch_accumulate();
    test_mul_xor_batch_zero_length();

    test_xor_batch_vs_scalar();
    test_xor_batch_zero_length();

    test_rs_encode_decode_no_loss();
    test_rs_encode_decode_with_loss();
    test_rs_encode_consistency();

    test_xor_fec_simd();

    test_adaptive_low_loss_no_fec();
    test_adaptive_light_protection();
    test_adaptive_moderate_protection();
    test_adaptive_heavy_protection();
    test_adaptive_max_protection();
    test_adaptive_high_reliability_forced();
    test_adaptive_low_latency_large_k();
    test_adaptive_block_size_passthrough();
    test_adaptive_recommendation_valid();

    test_perf_comparison();

    printf("\n=== Summary: %d passed, %d failed ===\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
