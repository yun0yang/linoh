// fec.cpp — FEC 前向纠错实现（P5-B-1）
//
// 包含：
//   - GF(2^8) 有限域运算（查表加速）
//   - XOR FEC（M=1，简单异或）
//   - Reed-Solomon FEC（Vandermonde 矩阵 + 高斯消元解码）

#include "linoh/fec/fec.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>

// v3.3.0 突破3: SIMD 头文件必须在 namespace 外包含，
// 否则 intrinsic 函数声明会被放入匿名命名空间引发符号冲突。
// 注意：<intrin.h> 在 Windows 会间接包含 <windows.h>，引入 None 宏（wingdi.h）
// 与 FecType::None 冲突，必须定义 NOGDI 禁止 GDI 宏。
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#ifndef NOGDI
#define NOGDI
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <intrin.h>
#include <immintrin.h>
#define LINOH_SIMD_HAS_IMMINTRIN 1
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#include <immintrin.h>
#define LINOH_SIMD_HAS_IMMINTRIN 1
#endif

#include "linoh/util/logging.hpp"

namespace linoh::fec {

// ============================================================================
// FecConfig
// ============================================================================

bool FecConfig::valid() const noexcept {
    if (type == FecType::None) return true;
    if (data_blocks == 0 || recovery_blocks == 0) return false;
    if (block_size == 0) return false;
    // mp-L1 (v1.7.0.8): 加 block_size 上限 64MB，防止恶意配置触发巨型缓冲分配
    //   导致 OOM。64MB 覆盖视频 Jumbo Frame + 大 tensor shard 场景，
    //   单块 64MB × (K+M)max=256 = 16GB 已远超实际需求。
    constexpr std::size_t kMaxBlockSize = 64 * 1024 * 1024;  // 64 MB
    if (block_size > kMaxBlockSize) return false;
    if (type == FecType::Xor) {
        // XOR 只支持 M=1
        if (recovery_blocks != 1) return false;
    }
    if (type == FecType::ReedSolomon) {
        // GF(2^8) 限制 K+M ≤ 256
        if (data_blocks + recovery_blocks > 256) return false;
    }
    return true;
}

const char *fec_type_name(FecType t) noexcept {
    switch (t) {
        case FecType::None:         return "None";
        case FecType::Xor:          return "Xor";
        case FecType::ReedSolomon:  return "ReedSolomon";
    }
    return "Unknown";
}

// ============================================================================
// GF(2^8) 有限域运算
// 生成多项式：0x11D（x^8 + x^4 + x^3 + x^2 + 1）
// 生成元：0x02
// ============================================================================

namespace gf256 {

namespace {

// 对数表与指数表（启动时初始化）
struct Tables {
    std::array<std::uint8_t, 256> exp{};   // exp[i] = 0x02^i
    std::array<std::uint8_t, 256> log{};   // log[i] = log_0x02(i)

    Tables() {
        std::fill(log.begin(), log.end(), 0);
        std::uint8_t x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[i] = x;
            log[x] = static_cast<std::uint8_t>(i);
            // x *= 0x02 in GF(2^8)
            std::uint16_t v = static_cast<std::uint16_t>(x) << 1;
            if (v & 0x100) v ^= 0x11D;
            x = static_cast<std::uint8_t>(v);
        }
        exp[255] = exp[0];  // 循环
        // log[0] 未定义，置 0
    }
};

const Tables &tables() {
    static const Tables t;
    return t;
}

}  // namespace

std::uint8_t mul(std::uint8_t a, std::uint8_t b) noexcept {
    if (a == 0 || b == 0) return 0;
    const auto &t = tables();
    int e = t.log[a] + t.log[b];
    if (e >= 255) e -= 255;
    return t.exp[e];
}

std::uint8_t div(std::uint8_t a, std::uint8_t b) noexcept {
    if (a == 0) return 0;
    if (b == 0) return 0;  // 未定义，返回 0
    const auto &t = tables();
    int e = t.log[a] - t.log[b];
    if (e < 0) e += 255;
    return t.exp[e];
}

std::uint8_t pow(std::uint8_t a, std::uint8_t e) noexcept {
    if (a == 0) return 0;
    if (e == 0) return 1;
    const auto &t = tables();
    int ee = static_cast<int>(t.log[a]) * e;
    ee %= 255;
    return t.exp[ee];
}

std::uint8_t inv(std::uint8_t a) noexcept {
    if (a == 0) return 0;
    const auto &t = tables();
    int e = 255 - t.log[a];
    return t.exp[e];
}

const std::uint8_t *exp_table() noexcept {
    return tables().exp.data();
}

const std::uint8_t *log_table() noexcept {
    return tables().log.data();
}

}  // namespace gf256

// ============================================================================
// XOR FEC（M=1，简单异或校验）
// ============================================================================

class XorFecEncoder : public FecEncoder {
public:
    explicit XorFecEncoder(FecConfig cfg) : cfg_(std::move(cfg)) {}

    std::vector<std::vector<std::uint8_t>> encode(
        std::span<const std::span<const std::uint8_t>> data_blocks) override {
        std::vector<std::vector<std::uint8_t>> result;
        if (data_blocks.size() != cfg_.data_blocks) {
            LINOH_ERROR("XorFecEncoder: data_blocks.size=%zu != K=%zu",
                        data_blocks.size(), cfg_.data_blocks);
            return result;
        }
        // 前 K 个原数据
        for (auto &blk : data_blocks) {
            if (blk.size() != cfg_.block_size) {
                LINOH_ERROR("XorFecEncoder: block size mismatch %zu != %zu",
                            blk.size(), cfg_.block_size);
                return result;
            }
            result.emplace_back(blk.begin(), blk.end());
        }
        // 1 个冗余块 = 所有数据块异或
        // v3.3.0 突破3: SIMD 批量 XOR（AVX2 一次 32 字节）
        std::vector<std::uint8_t> parity(cfg_.block_size, 0);
        for (auto &blk : data_blocks) {
            gf256::simd::xor_batch(blk.data(), parity.data(), cfg_.block_size);
        }
        result.push_back(std::move(parity));
        return result;
    }

    const FecConfig &config() const override { return cfg_; }

private:
    FecConfig cfg_;
};

class XorFecDecoder : public FecDecoder {
public:
    explicit XorFecDecoder(FecConfig cfg) : cfg_(std::move(cfg)) {}

    std::optional<std::vector<std::vector<std::uint8_t>>> decode(
        std::span<const std::optional<std::vector<std::uint8_t>>> received) override {
        // received 包含 K+M = K+1 个槽位
        if (received.size() != cfg_.data_blocks + 1) {
            return std::nullopt;
        }
        // 统计丢失
        std::size_t missing = 0;
        std::size_t missing_idx = 0;
        for (std::size_t i = 0; i < received.size(); ++i) {
            if (!received[i].has_value()) {
                ++missing;
                missing_idx = i;
            }
        }
        if (missing == 0) {
            // 全部到齐，返回前 K 个
            std::vector<std::vector<std::uint8_t>> result;
            for (std::size_t i = 0; i < cfg_.data_blocks; ++i) {
                result.push_back(*received[i]);
            }
            return result;
        }
        if (missing > 1) {
            // XOR 只能恢复 1 块
            return std::nullopt;
        }
        // 1 块丢失，用异或恢复
        // v3.3.0 突破3: SIMD 批量 XOR
        std::vector<std::uint8_t> recovered(cfg_.block_size, 0);
        for (std::size_t i = 0; i < received.size(); ++i) {
            if (i == missing_idx) continue;
            if (!received[i].has_value()) continue;  // 不应发生
            const auto &blk = *received[i];
            if (blk.size() != cfg_.block_size) return std::nullopt;
            gf256::simd::xor_batch(blk.data(), recovered.data(), cfg_.block_size);
        }
        // 构造结果
        std::vector<std::vector<std::uint8_t>> result;
        for (std::size_t i = 0; i < cfg_.data_blocks; ++i) {
            if (i == missing_idx) {
                result.push_back(recovered);
            } else {
                result.push_back(*received[i]);
            }
        }
        return result;
    }

    const FecConfig &config() const override { return cfg_; }

private:
    FecConfig cfg_;
};

// ============================================================================
// Reed-Solomon FEC（Vandermonde 矩阵 + 高斯消元）
// ============================================================================

class ReedSolomonEncoder : public FecEncoder {
public:
    explicit ReedSolomonEncoder(FecConfig cfg) : cfg_(std::move(cfg)) {
        build_matrix();
    }

    std::vector<std::vector<std::uint8_t>> encode(
        std::span<const std::span<const std::uint8_t>> data_blocks) override {
        std::vector<std::vector<std::uint8_t>> result;
        if (data_blocks.size() != cfg_.data_blocks) {
            LINOH_ERROR("RSEncoder: data_blocks.size=%zu != K=%zu",
                        data_blocks.size(), cfg_.data_blocks);
            return result;
        }
        // 前 K 个原数据
        for (auto &blk : data_blocks) {
            if (blk.size() != cfg_.block_size) {
                LINOH_ERROR("RSEncoder: block size mismatch");
                return result;
            }
            result.emplace_back(blk.begin(), blk.end());
        }
        // 后 M 个冗余块 = matrix[K..K+M) × data
        // matrix 行优先存储：(K+M) × K
        // v3.3.0 突破3: 内层循环改用 SIMD 批量 GF(256) 乘法（AVX2 一次 32 字节）
        for (std::size_t r = cfg_.data_blocks; r < cfg_.data_blocks + cfg_.recovery_blocks; ++r) {
            std::vector<std::uint8_t> parity(cfg_.block_size, 0);
            for (std::size_t c = 0; c < cfg_.data_blocks; ++c) {
                std::uint8_t coef = matrix_[r * cfg_.data_blocks + c];
                if (coef == 0) continue;
                const auto &blk = data_blocks[c];
                // SIMD: parity[i] ^= mul(coef, blk[i])，一次处理 32 字节（AVX2）
                gf256::simd::mul_xor_batch(coef, blk.data(), parity.data(), cfg_.block_size);
            }
            result.push_back(std::move(parity));
        }
        return result;
    }

    const FecConfig &config() const override { return cfg_; }

    /// 获取编码矩阵（用于测试）
    const std::vector<std::uint8_t> &matrix() const { return matrix_; }

private:
    FecConfig cfg_;
    std::vector<std::uint8_t> matrix_;  // (K+M) × K 行优先

    /// 构建 Vandermonde 编码矩阵
    /// 前 K 行：单位矩阵
    /// 后 M 行：Vandermonde 矩阵（alpha^i，i=1..M，alpha=生成元）
    void build_matrix() {
        std::size_t K = cfg_.data_blocks;
        std::size_t M = cfg_.recovery_blocks;
        matrix_.assign((K + M) * K, 0);
        // 前 K 行：单位矩阵
        for (std::size_t i = 0; i < K; ++i) {
            matrix_[i * K + i] = 1;
        }
        // 后 M 行：Vandermonde 矩阵
        // 第 K+i 行第 j 列 = alpha^(i*j)，alpha=0x02（生成元）
        // 用 alpha=2 的幂：v[i][j] = 2^(i*j) mod 0x11D
        // mp-P6 (v1.7.0.8): gf256::pow → 迭代乘法
        //   外层 i 固定后 alpha_base = 0x02^(i+1)，第 j 列 = alpha_base^j
        for (std::size_t i = 0; i < M; ++i) {
            std::uint8_t alpha_base = gf256::pow(0x02, static_cast<std::uint8_t>(i + 1));
            std::uint8_t alpha_pow = 1;  // alpha_base^0 = 1
            for (std::size_t j = 0; j < K; ++j) {
                matrix_[(K + i) * K + j] = alpha_pow;
                alpha_pow = gf256::mul(alpha_pow, alpha_base);  // 迭代乘法
            }
        }
    }
};

class ReedSolomonDecoder : public FecDecoder {
public:
    // mp-P5 (v1.7.0.8): 构造时缓存 full_matrix，避免每次 decode 重建
    explicit ReedSolomonDecoder(FecConfig cfg) : cfg_(std::move(cfg)) {
        cached_full_matrix_ = build_full_matrix_impl_();
    }

    std::optional<std::vector<std::vector<std::uint8_t>>> decode(
        std::span<const std::optional<std::vector<std::uint8_t>>> received) override {
        std::size_t K = cfg_.data_blocks;
        std::size_t M = cfg_.recovery_blocks;
        if (received.size() != K + M) return std::nullopt;

        // 统计丢失
        std::size_t missing = 0;
        for (std::size_t i = 0; i < received.size(); ++i) {
            if (!received[i].has_value()) ++missing;
        }
        if (missing == 0) {
            // 全部到齐，返回前 K 个
            std::vector<std::vector<std::uint8_t>> result;
            for (std::size_t i = 0; i < K; ++i) {
                result.push_back(*received[i]);
            }
            return result;
        }
        if (missing > M) {
            // 丢失数超过冗余数，无法恢复
            return std::nullopt;
        }

        // 重建编码矩阵：选择 K 个未丢失的块对应的矩阵行
        // 求解：data = inverse(selected_matrix) × selected_received
        std::vector<std::uint8_t> selected_matrix;  // K × K
        std::vector<std::vector<std::uint8_t>> selected_received;  // K 个块

        // 重建原始编码矩阵（与 encoder 一致）
        // mp-P5 (v1.7.0.8): 使用构造时缓存的 full_matrix，避免每次 decode 重建
        const std::vector<std::uint8_t> &full_matrix = cached_full_matrix_;

        std::size_t selected = 0;
        for (std::size_t i = 0; i < K + M && selected < K; ++i) {
            if (received[i].has_value()) {
                for (std::size_t j = 0; j < K; ++j) {
                    selected_matrix.push_back(full_matrix[i * K + j]);
                }
                selected_received.push_back(*received[i]);
                ++selected;
            }
        }
        if (selected < K) return std::nullopt;  // 不够 K 个

        // v1.7.0.6 性能优化：预消元矩阵一次，记录变换序列，
        // 对每个字节位置只应用变换（O(K³ + block_size × K²) 替代 O(block_size × K³)）
        // 变换记录格式：(target_row, source_row, factor) 表示 rhs[target] ^= factor × rhs[source]
        struct RowOp {
            std::size_t target;
            std::size_t source;
            std::uint8_t factor;
            bool is_swap;  // true=交换 target/source 行，false=异或
        };
        std::vector<RowOp> ops;
        std::vector<std::uint8_t> A = selected_matrix;
        bool singular = false;

        // Gauss-Jordan 消元，记录所有行变换
        for (std::size_t pivot = 0; pivot < K; ++pivot) {
            std::size_t pivot_row = pivot;
            while (pivot_row < K && A[pivot_row * K + pivot] == 0) ++pivot_row;
            if (pivot_row == K) { singular = true; break; }

            if (pivot_row != pivot) {
                for (std::size_t j = 0; j < K; ++j) {
                    std::swap(A[pivot * K + j], A[pivot_row * K + j]);
                }
                ops.push_back({pivot, pivot_row, 0, true});
            }

            std::uint8_t pivot_val = A[pivot * K + pivot];
            std::uint8_t pivot_inv = gf256::inv(pivot_val);
            for (std::size_t j = 0; j < K; ++j) {
                A[pivot * K + j] = gf256::mul(A[pivot * K + j], pivot_inv);
            }
            // 归一化主元行：rhs[pivot] *= pivot_inv
            ops.push_back({pivot, pivot, pivot_inv, false});

            for (std::size_t r = 0; r < K; ++r) {
                if (r == pivot) continue;
                std::uint8_t factor = A[r * K + pivot];
                if (factor == 0) continue;
                for (std::size_t j = 0; j < K; ++j) {
                    A[r * K + j] ^= gf256::mul(factor, A[pivot * K + j]);
                }
                ops.push_back({r, pivot, factor, false});
            }
        }
        if (singular) return std::nullopt;

        // 对每个字节位置应用变换序列
        std::vector<std::vector<std::uint8_t>> data_blocks(K, std::vector<std::uint8_t>(cfg_.block_size, 0));
        std::vector<std::uint8_t> rhs(K);
        for (std::size_t byte_idx = 0; byte_idx < cfg_.block_size; ++byte_idx) {
            for (std::size_t i = 0; i < K; ++i) {
                rhs[i] = selected_received[i][byte_idx];
            }
            for (const auto &op : ops) {
                if (op.is_swap) {
                    std::swap(rhs[op.target], rhs[op.source]);
                } else if (op.target == op.source) {
                    // 归一化：rhs[pivot] *= pivot_inv
                    rhs[op.target] = gf256::mul(rhs[op.target], op.factor);
                } else {
                    rhs[op.target] ^= gf256::mul(op.factor, rhs[op.source]);
                }
            }
            for (std::size_t i = 0; i < K; ++i) {
                data_blocks[i][byte_idx] = rhs[i];
            }
        }
        return data_blocks;
    }

    const FecConfig &config() const override { return cfg_; }

private:
    FecConfig cfg_;

    // mp-P5 (v1.7.0.8): 构造时调用的实际构建函数
    std::vector<std::uint8_t> build_full_matrix_impl_() const {
        std::size_t K = cfg_.data_blocks;
        std::size_t M = cfg_.recovery_blocks;
        std::vector<std::uint8_t> mat((K + M) * K, 0);
        for (std::size_t i = 0; i < K; ++i) {
            mat[i * K + i] = 1;
        }
        // mp-P6 (v1.7.0.8): build_matrix 每元素 gf256::pow → 迭代乘法
        //   gf256::pow(0x02, n) = 0x02 乘自身 n 次，迭代乘法比 pow（含对数表查找）快
        //   外层 i 固定后 alpha_base = 0x02^(i+1)，第 j 列 = alpha_base^j
        //   用迭代：col_j = col_(j-1) * alpha_base，避免每次 pow 查表
        for (std::size_t i = 0; i < M; ++i) {
            // alpha_base = 0x02 ^ (i+1)，用一次 pow 计算（M 次 pow 替代 M*K 次）
            std::uint8_t alpha_base = gf256::pow(0x02, static_cast<std::uint8_t>(i + 1));
            std::uint8_t alpha_pow = 1;  // alpha_base^0 = 1
            for (std::size_t j = 0; j < K; ++j) {
                mat[(K + i) * K + j] = alpha_pow;
                alpha_pow = gf256::mul(alpha_pow, alpha_base);  // 迭代乘法
            }
        }
        return mat;
    }

    // mp-P5 (v1.7.0.8): 缓存的 full_matrix（构造时计算，decode 时复用）
    std::vector<std::uint8_t> cached_full_matrix_;

    // v1.7.0.6 性能优化: gaussian_elimination 已内联到 decode() 中，
    // 预消元矩阵一次 + 对每个字节位置只应用变换序列，避免重复消元
};

// ============================================================================
// v3.3.0 突破3: SIMD 加速 + 自适应恢复
// ============================================================================

// 注意：gf256 命名空间在第 149 行已关闭（mul/div/pow/inv 等基础运算）。
// 此处重新开启 gf256 命名空间，包裹 SIMD 实现部分，使其与 fec.hpp 中的
// 声明（linoh::fec::gf256::detect_cpu_features / linoh::fec::gf256::simd::*）匹配。
namespace gf256 {

namespace {

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#define LINOH_HAS_X86_CPUID 1
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#define LINOH_HAS_X86_CPUID 1
#include <cpuid.h>
#endif

/// 检测 x86 CPU SIMD 特征（运行时一次检测，缓存到 CpuFeatures）
CpuFeatures detect_x86_features() noexcept {
    CpuFeatures f{};
#if defined(LINOH_HAS_X86_CPUID)
#if defined(_MSC_VER)
    int info[4];
    __cpuid(info, 0);
    int nids = info[0];
    if (nids >= 1) {
        __cpuidex(info, 1, 0);
        f.has_sse2  = (info[3] & (1 << 26)) != 0;
        f.has_ssse3 = (info[2] & (1 << 9))  != 0;
    }
    if (nids >= 7) {
        __cpuidex(info, 7, 0);
        f.has_avx2 = (info[1] & (1 << 5))  != 0;
        // AVX512-VL: CPUID.07h:EBX.bit16 (AVX512F) + CPUID.07h:ECX.bit1 (AVX512VL)
        // 简化：仅检测 AVX512F 作为代表（实际部署 RTX 4090 等机器普遍支持）
        f.has_avx512 = (info[1] & (1 << 16)) != 0;
    }
#else
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        f.has_sse2  = (edx & (1 << 26)) != 0;
        f.has_ssse3 = (ecx & (1 << 9))  != 0;
    }
    unsigned int eax7, ebx7, ecx7, edx7;
    if (__get_cpuid_count(7, 0, &eax7, &ebx7, &ecx7, &edx7)) {
        f.has_avx2 = (ebx7 & (1 << 5))  != 0;
        f.has_avx512 = (ebx7 & (1 << 16)) != 0;
    }
#endif
#endif
    return f;
}

}  // namespace

const CpuFeatures &detect_cpu_features() noexcept {
    static const CpuFeatures cached = detect_x86_features();
    return cached;
}

namespace simd {

namespace {

/// 预计算固定系数 coef 的乘法查找表（GF(256) PSHUFB 方案）
///
/// 将 8 位输入拆分为低 4 位 + 高 4 位，分别用 PSHUFB 查表：
///   in = high_nibble << 4 | low_nibble
///   mul(coef, in) = mul(coef, high_nibble << 4) ^ mul(coef, low_nibble)
///                 = high_table[high_nibble] ^ low_table[low_nibble]
///
/// 每张表 16 字节（nibble 0-15），可装入一个 __m128i。
struct CoefMulTable {
    alignas(16) std::uint8_t low[16];   ///< low_table[i] = mul(coef, i)
    alignas(16) std::uint8_t high[16];  ///< high_table[i] = mul(coef, i << 4)

    explicit CoefMulTable(std::uint8_t coef) noexcept {
        for (int i = 0; i < 16; ++i) {
            low[i]  = gf256::mul(coef, static_cast<std::uint8_t>(i));
            high[i] = gf256::mul(coef, static_cast<std::uint8_t>(i << 4));
        }
    }
};

/// 标量回退路径：out[i] ^= mul(coef, in[i])
void mul_xor_scalar(std::uint8_t coef,
                    const std::uint8_t *in,
                    std::uint8_t *out,
                    std::size_t n) noexcept {
    if (coef == 0) return;  // 乘 0 结果为 0，XOR 无变化
    for (std::size_t i = 0; i < n; ++i) {
        out[i] ^= gf256::mul(coef, in[i]);
    }
}

/// 标量回退路径：out[i] ^= in[i]
void xor_scalar(const std::uint8_t *in,
                std::uint8_t *out,
                std::size_t n) noexcept {
    for (std::size_t i = 0; i < n; ++i) {
        out[i] ^= in[i];
    }
}

#if defined(LINOH_SIMD_HAS_IMMINTRIN)
/// AVX2 / SSSE3 路径：out[i] ^= mul(coef, in[i])，一次 16 字节（SSSE3）或 32 字节（AVX2）
void mul_xor_ssse3(std::uint8_t coef,
                   const std::uint8_t *in,
                   std::uint8_t *out,
                   std::size_t n) noexcept {
    if (coef == 0) return;
    const CoefMulTable tbl(coef);
    const __m128i low_tbl  = _mm_load_si128(reinterpret_cast<const __m128i *>(tbl.low));
    const __m128i high_tbl = _mm_load_si128(reinterpret_cast<const __m128i *>(tbl.high));
    const __m128i mask_low  = _mm_set1_epi8(0x0F);
    // 高 4 位提取：右移 4 后再 mask（注意带符号算术右移需先 and）
    const __m128i mask_high_shift = _mm_set1_epi8(static_cast<char>(0xF0));

    std::size_t i = 0;
    // SSSE3: 一次 16 字节
    for (; i + 16 <= n; i += 16) {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i *>(in + i));
        __m128i lo = _mm_and_si128(v, mask_low);
        __m128i hi = _mm_and_si128(v, mask_high_shift);
        hi = _mm_srli_epi16(hi, 4);  // 逻辑右移 4 位
        hi = _mm_and_si128(hi, mask_low);
        __m128i lo_mul = _mm_shuffle_epi8(low_tbl, lo);
        __m128i hi_mul = _mm_shuffle_epi8(high_tbl, hi);
        __m128i result = _mm_xor_si128(lo_mul, hi_mul);
        __m128i out_v = _mm_loadu_si128(reinterpret_cast<const __m128i *>(out + i));
        out_v = _mm_xor_si128(out_v, result);
        _mm_storeu_si128(reinterpret_cast<__m128i *>(out + i), out_v);
    }
    // 尾部标量
    if (i < n) {
        mul_xor_scalar(coef, in + i, out + i, n - i);
    }
}

/// AVX2 路径：一次 32 字节（两个独立 128 位 PSHUFB）
void mul_xor_avx2(std::uint8_t coef,
                  const std::uint8_t *in,
                  std::uint8_t *out,
                  std::size_t n) noexcept {
    if (coef == 0) return;
    const CoefMulTable tbl(coef);
    const __m128i low_tbl  = _mm_load_si128(reinterpret_cast<const __m128i *>(tbl.low));
    const __m128i high_tbl = _mm_load_si128(reinterpret_cast<const __m128i *>(tbl.high));
    const __m256i mask_low  = _mm256_set1_epi8(0x0F);
    const __m256i mask_high_shift = _mm256_set1_epi8(static_cast<char>(0xF0));

    std::size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(in + i));
        __m256i lo = _mm256_and_si256(v, mask_low);
        __m256i hi = _mm256_and_si256(v, mask_high_shift);
        hi = _mm256_srli_epi16(hi, 4);
        hi = _mm256_and_si256(hi, mask_low);
        // AVX2 的 _mm256_shuffle_epi8 是两个独立 128 位 lane shuffle，
        // 表在每个 lane 内相同，所以可以直接用
        __m256i lo_mul = _mm256_shuffle_epi8(_mm256_broadcastsi128_si256(low_tbl), lo);
        __m256i hi_mul = _mm256_shuffle_epi8(_mm256_broadcastsi128_si256(high_tbl), hi);
        __m256i result = _mm256_xor_si256(lo_mul, hi_mul);
        __m256i out_v = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(out + i));
        out_v = _mm256_xor_si256(out_v, result);
        _mm256_storeu_si256(reinterpret_cast<__m256i *>(out + i), out_v);
    }
    // 尾部 16 字节（SSSE3）+ 标量
    if (i + 16 <= n) {
        mul_xor_ssse3(coef, in + i, out + i, n - i);
    } else if (i < n) {
        mul_xor_scalar(coef, in + i, out + i, n - i);
    }
}

/// SSSE3 XOR：一次 16 字节
void xor_ssse3(const std::uint8_t *in, std::uint8_t *out, std::size_t n) noexcept {
    std::size_t i = 0;
    for (; i + 16 <= n; i += 16) {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i *>(in + i));
        __m128i o = _mm_loadu_si128(reinterpret_cast<const __m128i *>(out + i));
        o = _mm_xor_si128(o, v);
        _mm_storeu_si128(reinterpret_cast<__m128i *>(out + i), o);
    }
    if (i < n) xor_scalar(in + i, out + i, n - i);
}

/// AVX2 XOR：一次 32 字节
void xor_avx2(const std::uint8_t *in, std::uint8_t *out, std::size_t n) noexcept {
    std::size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(in + i));
        __m256i o = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(out + i));
        o = _mm256_xor_si256(o, v);
        _mm256_storeu_si256(reinterpret_cast<__m256i *>(out + i), o);
    }
    if (i + 16 <= n) {
        xor_ssse3(in + i, out + i, n - i);
    } else if (i < n) {
        xor_scalar(in + i, out + i, n - i);
    }
}
#endif  // LINOH_SIMD_HAS_IMMINTRIN

}  // namespace

void mul_xor_batch(std::uint8_t coef,
                   const std::uint8_t *in,
                   std::uint8_t *out,
                   std::size_t n) noexcept {
#if defined(LINOH_SIMD_HAS_IMMINTRIN)
    const auto &cpu = detect_cpu_features();
    if (cpu.has_avx2) {
        mul_xor_avx2(coef, in, out, n);
        return;
    }
    if (cpu.has_ssse3) {
        mul_xor_ssse3(coef, in, out, n);
        return;
    }
#endif
    (void)coef;  // 抑制未使用警告（已在标量内部处理）
    mul_xor_scalar(coef, in, out, n);
}

void xor_batch(const std::uint8_t *in, std::uint8_t *out, std::size_t n) noexcept {
#if defined(LINOH_SIMD_HAS_IMMINTRIN)
    const auto &cpu = detect_cpu_features();
    if (cpu.has_avx2) {
        xor_avx2(in, out, n);
        return;
    }
    if (cpu.has_ssse3) {
        xor_ssse3(in, out, n);
        return;
    }
#endif
    xor_scalar(in, out, n);
}

const char *active_backend() noexcept {
#if defined(LINOH_SIMD_HAS_IMMINTRIN)
    const auto &cpu = detect_cpu_features();
    if (cpu.has_avx2)   return "AVX2";
    if (cpu.has_ssse3)  return "SSSE3";
#endif
    return "Scalar";
}

}  // namespace simd
}  // namespace gf256

// ============================================================================
// v3.3.0 突破3: 自适应 FEC 恢复配置
// ============================================================================

namespace adaptive {

FecRecommendation recommend_fec_config(const NetworkQuality &quality,
                                       FecProfile profile,
                                       std::size_t block_size) noexcept {
    FecRecommendation rec;
    rec.block_size = (block_size == 0) ? 1024 : block_size;

    const double loss = quality.loss_rate;

    // HighReliability 场景强制启用 FEC（即使低丢包）
    if (profile == FecProfile::HighReliability) {
        if (loss < 0.001) {
            // 低丢包 + 高可靠：轻度保护
            rec.type = FecType::ReedSolomon;
            rec.data_blocks = 16;
            rec.recovery_blocks = 1;
            rec.reason = "HighReliability profile, low loss, light RS protection";
            return rec;
        }
        // 否则按通用逻辑决策（fall through）
    }

    // 决策表（按丢包率）
    if (loss < 0.001) {
        // < 0.1%: QUIC 重传足够，FEC 开销不划算
        rec.type = FecType::None;
        rec.data_blocks = 0;
        rec.recovery_blocks = 0;
        rec.reason = "loss<0.1%, QUIC retransmit sufficient, FEC overhead not warranted";
    } else if (loss < 0.01) {
        // 0.1%-1%: 轻度保护
        rec.type = FecType::ReedSolomon;
        rec.data_blocks = 16;
        rec.recovery_blocks = 1;
        rec.reason = "loss 0.1%-1%, light RS protection (K=16 M=1)";
    } else if (loss < 0.05) {
        // 1%-5%: 中度保护
        rec.type = FecType::ReedSolomon;
        rec.data_blocks = 10;
        rec.recovery_blocks = 2;
        rec.reason = "loss 1%-5%, moderate RS protection (K=10 M=2)";
    } else if (loss < 0.10) {
        // 5%-10%: 重度保护
        rec.type = FecType::ReedSolomon;
        rec.data_blocks = 8;
        rec.recovery_blocks = 3;
        rec.reason = "loss 5%-10%, heavy RS protection (K=8 M=3)";
    } else {
        // > 10%: 最大保护 + 建议排查网络
        rec.type = FecType::ReedSolomon;
        rec.data_blocks = 6;
        rec.recovery_blocks = 4;
        rec.reason = "loss>10%, max RS protection (K=6 M=4), network investigation recommended";
    }

    // LowLatency 场景：K 更大（分摊开销），M 不变（恢复能力不降）
    if (profile == FecProfile::LowLatency && rec.type != FecType::None) {
        if (rec.data_blocks < 16) {
            rec.data_blocks = 16;  // 低延迟用大 K 降低单块开销
            rec.reason = "LowLatency profile, larger K to reduce per-block overhead";
        }
    }

    return rec;
}

}  // namespace adaptive

// ============================================================================
// 工厂函数
// ============================================================================

std::unique_ptr<FecEncoder> create_encoder(const FecConfig &config) {
    if (!config.valid()) {
        LINOH_ERROR("create_encoder: invalid config (type=%s K=%zu M=%zu bs=%zu)",
                    fec_type_name(config.type), config.data_blocks,
                    config.recovery_blocks, config.block_size);
        return nullptr;
    }
    switch (config.type) {
        case FecType::None:
            return nullptr;  // 不启用 FEC
        case FecType::Xor:
            return std::make_unique<XorFecEncoder>(config);
        case FecType::ReedSolomon:
            return std::make_unique<ReedSolomonEncoder>(config);
    }
    return nullptr;
}

std::unique_ptr<FecDecoder> create_decoder(const FecConfig &config) {
    if (!config.valid()) {
        LINOH_ERROR("create_decoder: invalid config (type=%s K=%zu M=%zu bs=%zu)",
                    fec_type_name(config.type), config.data_blocks,
                    config.recovery_blocks, config.block_size);
        return nullptr;
    }
    switch (config.type) {
        case FecType::None:
            return nullptr;
        case FecType::Xor:
            return std::make_unique<XorFecDecoder>(config);
        case FecType::ReedSolomon:
            return std::make_unique<ReedSolomonDecoder>(config);
    }
    return nullptr;
}

}  // namespace linoh::fec
