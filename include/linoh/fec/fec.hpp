// fec.hpp — FEC 前向纠错（P5-B-1）
//
// 借鉴 Sunshine Reed-Solomon FEC（rs.h，minRequiredFecPackets）思想：
//   - 在数据块之外生成 M 个冗余块，接收端丢失 ≤ M 个数据块时可恢复
//   - 适用于视频/LLM 等不可丢场景，减少重传
//   - LLM hidden_state：RS K=10 M=2（高保护）
//   - 视频特征：RS K=16 M=1（轻度保护）
//   - 图片/控制信道：None（依赖 QUIC reliable stream）
//
// 实现两种 FEC：
//   - XorFecEncoder/Decoder：M=1，简单异或校验（O(K) 编码，O(K) 解码）
//   - ReedSolomonEncoder/Decoder：基于 GF(2^8) Vandermonde 矩阵（M 任意）
//
// GF(2^8) 参数：
//   - 生成多项式：0x11D（x^8 + x^4 + x^3 + x^2 + 1）
//   - 生成元：0x02
//   - 支持最多 256 个块（K+M ≤ 256）
//
// 设计原则：
//   - 块大小固定（block_size），上层负责把数据切片
//   - 编码：输入 K 个数据块，输出 K+M 个块（前 K 个原数据 + 后 M 个冗余）
//   - 解码：输入收到的块及对应索引，输出恢复后的 K 个数据块
//   - 接口抽象（FecEncoder/FecDecoder），工厂按 FecType 创建

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace linoh::fec {

/// FEC 类型
enum class FecType : std::uint8_t {
    None          = 0,  // 不启用 FEC
    Xor           = 1,  // XOR 简单奇偶校验（M=1，K 任意）
    ReedSolomon   = 2,  // RS 纠错码（M 任意，K 任意，基于 GF(2^8)）
};

/// FEC 配置
struct FecConfig {
    FecType     type{FecType::None};
    std::size_t data_blocks{10};       // K：数据块数
    std::size_t recovery_blocks{2};    // M：冗余块数
    std::size_t block_size{1024};      // 单块字节数

    /// 校验配置是否合法
    bool valid() const noexcept;
};

/// FEC 编码器接口
class FecEncoder {
public:
    virtual ~FecEncoder() = default;
    /// 输入 K 个数据块，输出 K+M 个块（前 K 个原数据，后 M 个冗余）
    /// \param data_blocks K 个数据块，每块大小 = config.block_size
    /// \return K+M 个块
    virtual std::vector<std::vector<std::uint8_t>> encode(
        std::span<const std::span<const std::uint8_t>> data_blocks) = 0;

    /// 配置查询
    virtual const FecConfig &config() const = 0;
};

/// FEC 解码器接口
class FecDecoder {
public:
    virtual ~FecDecoder() = default;
    /// 输入收到的块（可能丢失部分），输出恢复后的 K 个数据块
    /// \param received 收到的块（按原始索引位置存放，丢失位置为 nullopt）
    /// \return 恢复成功返回 K 个数据块，失败返回 nullopt
    virtual std::optional<std::vector<std::vector<std::uint8_t>>> decode(
        std::span<const std::optional<std::vector<std::uint8_t>>> received) = 0;

    /// 配置查询
    virtual const FecConfig &config() const = 0;
};

/// 工厂函数
std::unique_ptr<FecEncoder> create_encoder(const FecConfig &config);
std::unique_ptr<FecDecoder> create_decoder(const FecConfig &config);

/// FEC 类型名称（用于日志）
const char *fec_type_name(FecType t) noexcept;

/// GF(2^8) 基本运算（公开供测试）
namespace gf256 {

/// GF(2^8) 乘法
std::uint8_t mul(std::uint8_t a, std::uint8_t b) noexcept;
/// GF(2^8) 除法（a / b，b ≠ 0）
std::uint8_t div(std::uint8_t a, std::uint8_t b) noexcept;
/// GF(2^8) 幂运算
std::uint8_t pow(std::uint8_t a, std::uint8_t e) noexcept;
/// GF(2^8) 逆元（a ≠ 0）
std::uint8_t inv(std::uint8_t a) noexcept;

/// 对数表（exp[i] = 0x02^i），用于查表加速
const std::uint8_t *exp_table() noexcept;
/// 对数表（log[i] = log_0x02(i)），用于查表加速
const std::uint8_t *log_table() noexcept;

// ============================================================================
// v3.3.0 突破3: SIMD 加速接口
// ============================================================================

/// CPU 特征检测结果
struct CpuFeatures {
    bool has_sse2{false};     ///< SSE2（x86 基线，PSHUFB 需要 SSSE3）
    bool has_ssse3{false};    ///< SSSE3（PSHUFB 指令）
    bool has_avx2{false};     ///< AVX2（256 位 PSHUFB，一次 32 字节）
    bool has_avx512{false};   ///< AVX512-VL（512 位，一次 64 字节）
    bool has_neon{false};     ///< ARM NEON（VTBL，一次 16 字节）
};

/// 运行时检测 CPU SIMD 特征（线程安全，首次调用后缓存）
/// \return 检测结果，失败时所有字段为 false（走标量回退路径）
const CpuFeatures &detect_cpu_features() noexcept;

namespace simd {

/// 批量 GF(256) 标量乘法：out[i] = mul(coef, in[i])，并 XOR 累加到 out[i]。
///
/// v3.3.0 突破3: 自动选择最优 SIMD 路径（AVX2/SSSE3/标量）。
/// - AVX2: 一次处理 32 字节（两个独立 128 位 PSHUFB）
/// - SSSE3: 一次处理 16 字节（单个 PSHUFB）
/// - 标量: 逐字节查 log/exp 表
///
/// \param coef 固定系数（编码矩阵元素）
/// \param in 输入数据块（block_size 字节）
/// \param out 输出累加缓冲（block_size 字节），out[i] ^= mul(coef, in[i])
/// \param n 字节数
void mul_xor_batch(std::uint8_t coef,
                   const std::uint8_t *in,
                   std::uint8_t *out,
                   std::size_t n) noexcept;

/// 批量 XOR：out[i] ^= in[i]（XOR FEC 编码用）。
/// 自动选择 AVX2/SSSE3/标量路径。
void xor_batch(const std::uint8_t *in,
               std::uint8_t *out,
               std::size_t n) noexcept;

/// 当前生效的 SIMD 后端名称（用于日志/统计）
const char *active_backend() noexcept;

}  // namespace simd
}  // namespace gf256

// ============================================================================
// v3.3.0 突破3: 自适应 FEC 恢复配置
// ============================================================================

namespace adaptive {

/// 网络质量观测值（供自适应建议器决策）
struct NetworkQuality {
    double loss_rate{0.0};          ///< 丢包率 [0.0, 1.0]
    double rtt_ms{0.0};             ///< 平滑 RTT（毫秒）
    double bandwidth_mbps{0.0};     ///< 可用带宽（Mbps，0=未知）
};

/// FEC 应用场景（影响 K/M 权衡）
enum class FecProfile {
    LowLatency = 0,   ///< 低延迟（LLM hidden_state，优先恢复速度）
    Balanced   = 1,   ///< 平衡（视频特征流，恢复 + 开销均衡）
    HighReliability = 2, ///< 高可靠（控制信令，最大恢复能力）
};

/// 自适应 FEC 配置建议
struct FecRecommendation {
    FecType type{FecType::None};
    std::size_t data_blocks{10};       ///< K
    std::size_t recovery_blocks{2};    ///< M
    std::size_t block_size{1024};      ///< 单块字节数
    const char *reason{""};            ///< 决策原因（日志用）
};

/// 根据网络质量 + 应用场景推荐 FEC 配置。
///
/// 决策逻辑：
/// - loss_rate < 0.1%: 不启用 FEC（QUIC 重传足够，FEC 开销不划算）
/// - loss_rate 0.1%-1%: 轻度保护（RS K=16 M=1）
/// - loss_rate 1%-5%: 中度保护（RS K=10 M=2）
/// - loss_rate 5%-10%: 重度保护（RS K=8 M=3）
/// - loss_rate > 10%: 最大保护（RS K=6 M=4）+ 建议排查网络
/// - HighReliability 场景强制启用 FEC（即使低丢包）
///
/// \param quality 网络质量观测值
/// \param profile 应用场景
/// \param block_size 单块字节数（0=使用默认 1024）
FecRecommendation recommend_fec_config(const NetworkQuality &quality,
                                       FecProfile profile = FecProfile::Balanced,
                                       std::size_t block_size = 0) noexcept;

}  // namespace adaptive

}  // namespace linoh::fec
