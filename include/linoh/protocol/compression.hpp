// compression.hpp — V3.4 按需压缩（zstd）
//
// 提供 compress_payload / decompress_payload / recommend_compression 三个接口，
// 供 ApplicationMessage 在 serialize/parse 时按需压缩 payload（P3 集成阶段接入，
// 详见 docs/LINOH_EVENTBUS_BINARY_FRAME_IMPL_PLAN.md §3.3.4）。
//
// 压缩算法：
//   - Zstd：V3.4 推荐，压缩比 + 速度更优（基于 vendored zstd 1.5.6）
//   - Gzip：兼容既有 PayloadCompressed flag（V3.4 暂未实现，返回空 vector）
//   - None：不压缩（原样返回）
//
// 自动推荐规则（recommend_compression，O1 v2 按数学判据重写）：
//   | 条件 | 结论 |
//   | Heartbeat（小且高频） | None |
//   | payload < 300B | None（<300B 流式压缩为负收益，实测膨胀） |
//   | ForwardPP / ResultPP >= 1KB | Zstd（浮点尾数熵高，收益有限但无害） |
//   | 结构化控制面方法 >= 300B | Zstd（1–16KB 区间为字典压缩主战场） |
//   | Tensor 分片族 / Observe / 认证帧 | None（与分片缓冲/hash 语义解耦） |
//   | 其他/未知方法 >= 16KB | Zstd（与旧规则一致） |

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "linoh/protocol/application_message.hpp"  // MethodId

namespace linoh::protocol {

/// 压缩算法枚举
enum class CompressionAlgo : std::uint8_t {
    None  = 0,
    Gzip  = 1,  // 兼容既有 PayloadCompressed flag（V3.4 暂未实现，返回空）
    Zstd  = 2,  // V3.4 推荐，压缩比 + 速度更优
};

/// 默认 zstd 压缩级别（1-22，3 是速度/压缩比平衡点）
constexpr int kDefaultZstdLevel = 3;

/// 压缩 payload（按算法选择）
/// @param in 原始 payload
/// @param algo 压缩算法（None=原样返回，Gzip=未实现返回空，Zstd=压缩）
/// @param level 压缩级别（zstd: 1-22，0=使用默认 3；gzip: 1-9）
/// @return 压缩后字节流；失败或 Gzip 未实现返回空
std::vector<std::uint8_t> compress_payload(
    std::span<const std::uint8_t> in,
    CompressionAlgo algo,
    int level = 0);

/// 解压 payload
/// @param in 压缩字节流
/// @param algo 压缩算法
/// @param expected_size 预期解压大小（0=从 zstd 帧头自动解析）
/// @return 解压后字节流；失败返回空
std::vector<std::uint8_t> decompress_payload(
    std::span<const std::uint8_t> in,
    CompressionAlgo algo,
    std::size_t expected_size = 0);

/// 自动选择压缩算法（基于 payload 大小 + 消息类型）
/// @param payload_size payload 字节数
/// @param method 消息方法（不同方法有不同阈值）
/// @return 推荐算法（None=不压缩）
CompressionAlgo recommend_compression(
    std::size_t payload_size,
    MethodId method);

// ============================================================
// O1（cluster 优化总体方案 v1.0 / linoh 编码层方案）：
// 协议字典压缩 + 自动压缩开关
//
// 数学依据（编码层方案 §1.5）：短消息的先验在消息之间——同一协议的
// 消息共享 schema/字段名/URL 前缀，字典把 H(X) 降为 H(X|D)。
// 实测：4KB 结构化任务消息 -92.7%（vs 无字典 zstd -68.6%）。
//
// wire 格式（与 ZstdCompressed flag 互斥，新 flag ZstdDictCompressed）：
//   payload = [dict_id: 1B][zstd frame（用 dict 压缩）]
// dict_id 支持最多 256 本字典轮换；协商联动走 CapabilitiesProbe
// （kCapZstdDict，O1.2）；旧节点不识别 flag 位 → 发送端须在能力
// 确认后才启用字典压缩（自动压缩开关默认 off，部署侧灰度开启）。
// ============================================================

/// 加载协议压缩字典（进程级，按 dict_id 注册，可覆盖同名）
/// @param dict_id 字典编号（写入 wire 首字节，0-255）
/// @param dict 字典内容（zstd dictionary 格式，由 ZDICT_trainFromBuffer 训练）
/// @return true=加载成功（内部缓存 ZSTD_CDict；失败时移除旧条目）
bool load_protocol_dict(std::uint8_t dict_id,
                        std::span<const std::uint8_t> dict);

/// 清除全部已加载字典
void clear_protocol_dicts();

/// 是否已加载指定 dict_id 的字典
bool has_protocol_dict(std::uint8_t dict_id);

/// 是否加载了任意字典（maybe_auto_compress 的字典优先条件）
bool has_any_protocol_dict() noexcept;

/// 最后加载的字典 id（无字典返回 0）
std::uint8_t default_dict_id() noexcept;

/// 字典压缩：输出 [dict_id: 1B][zstd frame]
/// @return 压缩字节流；失败或字典未加载返回空
std::vector<std::uint8_t> compress_payload_dict(
    std::span<const std::uint8_t> in,
    int level,
    std::uint8_t dict_id);

/// 字典解压：输入 [dict_id: 1B][zstd frame]，按首字节选字典
/// @return 解压字节流；字典缺失/格式错误/解压失败返回空
std::vector<std::uint8_t> decompress_payload_dict(
    std::span<const std::uint8_t> in);

/// 开启/关闭消息自动压缩（进程级，默认 off）
/// 开启后 Connection 发送 helper 在 serialize 前调用
/// ApplicationMessage::maybe_auto_compress()（按 recommend 规则 + 字典优先）
void set_auto_compress(bool on, int level = 3);

/// 查询自动压缩开关
bool auto_compress_enabled() noexcept;

/// 字典信息（部署侧校验两端一致性：同 id 同 size 同校验值）
struct ProtocolDictInfo {
    std::uint8_t  dict_id{0};
    std::size_t   size{0};      // 字典字节数
    std::uint64_t xxh64{0};     // 内容校验（XXH64，种子 0）
    bool          loaded{false};
};

/// 从文件加载字典（O1.3 工程化：部署侧直接指路径）
/// @param path 字典文件路径（zstd dictionary 格式，<=1MB）
/// @param dict_id 注册编号
/// @return true=加载成功
bool load_protocol_dict_file(const char *path, std::uint8_t dict_id);

/// 查询已注册字典的信息（未注册时 loaded=false）
ProtocolDictInfo protocol_dict_info(std::uint8_t dict_id);

}  // namespace linoh::protocol
