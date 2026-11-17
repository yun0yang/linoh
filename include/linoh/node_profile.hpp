// node_profile.hpp — 节点画像（v2.0 Phase 1）
//
// 四维 NodeProfile 结构：计算能力 / 网络能力 / 稳定性 / 地理
// 驱动 CommPlanner 拓扑规划与 orchestrator 调度决策。
//
// 设计原则：
//   - 画像驱动调度：一切调度决策以 NodeProfile 为输入，禁止静态配置
//   - 跨层共享：GeoRegion 复用 linoh/geo_region.hpp，避免重复定义
//   - 轻量解耦：NetClass 在本头文件独立定义，不依赖 tls::NetworkClass
//   - 线程安全：NodeProfileStore 全接口加锁，支持并发 upsert/get/erase
//   - 文本持久化：INI 风格 key=value，重启不丢失，便于人工核查
//
// 评分公式（详见 .cpp 实现）：
//   stability_score = 0.4*(1 - disconnect_count/24)
//                   + 0.3 * task_success_rate
//                   + 0.3 * min(uptime_seconds/86400, 1)
//   overall_score   = w_compute * compute_norm
//                   + w_network * network_norm
//                   + w_stability * stability_score
//                   + w_geo      * geo_norm
//   （所有子分均归一化到 [0,1]，overall_score ∈ [0,1]）

#pragma once

#include "linoh/base/key.hpp"      // base::EndpointId
#include "linoh/geo_region.hpp"     // GeoRegion

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace linoh {

// ============================================================================
// 网络分级（独立定义，与 tls::NetworkClass 解耦）
// ============================================================================

/// 网络环境分级（三档，与 tls::NetworkClass 语义一致但独立定义）
enum class NetClass : std::uint8_t {
    Lan  = 0,  // 局域网/公网直连（OpenInternet/FullCone）
    Wan  = 1,  // 广域网普通 NAT（RestrictedCone/PortRestrictedCone）
    Hard = 2,  // 困难网络（Symmetric/CGN/Unknown/UDP Blocked）
};

/// 网络分级转字符串（日志/持久化用）
constexpr const char *net_class_name(NetClass c) noexcept {
    switch (c) {
        case NetClass::Lan:  return "lan";
        case NetClass::Wan:  return "wan";
        case NetClass::Hard: return "hard";
    }
    return "unknown";
}

/// 从字符串解析网络分级
inline NetClass net_class_from_name(const std::string &name) {
    if (name == "lan")  return NetClass::Lan;
    if (name == "wan")  return NetClass::Wan;
    if (name == "hard") return NetClass::Hard;
    return NetClass::Lan;  // 未知默认 Lan（向后兼容）
}

// ============================================================================
// 时间点类型（复用 system_clock，与 relay_pool.hpp 一致）
// ============================================================================

using TimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// 评分权重
// ============================================================================

/// NodeProfile 综合评分权重（overall_score 各维度系数，总和应为 1.0）
struct NodeScoreWeights {
    double weight_compute{0.35};     // 计算能力权重
    double weight_network{0.25};     // 网络能力权重
    double weight_stability{0.30};   // 稳定性权重
    double weight_geo{0.10};         // 地理维度权重（同城加分）
};

// ============================================================================
// NodeProfile 四维结构
// ============================================================================

/// 节点画像（四维：计算 / 网络 / 稳定性 / 地理）
struct NodeProfile {
    base::EndpointId endpoint_id;
    std::string node_id;              // orchestrator node_id（可选关联）

    // ------------------------------------------------------------------
    // 维度 1：计算能力
    // ------------------------------------------------------------------
    struct ComputeCap {
        std::string gpu_model;        // "RTX 4090" / "RTX 3060" / ...
        std::uint32_t vram_mb{0};     // 显存（MB）
        float tflops_fp16{0.0f};      // FP16 算力（TFLOPS，基准测试估计）
        float tflops_int4{0.0f};      // INT4 算力（TFLOPS）
        std::uint32_t cuda_cores{0};  // CUDA 核心数

        /// 计算能力归一化分 [0,1]（以 RTX 4090 为基准 1.0）
        float normalized_score() const noexcept;
    } compute;

    // ------------------------------------------------------------------
    // 维度 2：网络能力
    // ------------------------------------------------------------------
    struct NetworkCap {
        std::uint32_t uplink_bps{0};     // 上行带宽（bps）
        std::uint32_t downlink_bps{0};   // 下行带宽（bps）
        std::uint32_t rtt_ms_avg{0};     // 平均 RTT（ms）
        std::uint32_t rtt_ms_p99{0};     // P99 RTT（ms）
        float loss_rate{0.0f};           // 丢包率 [0,1]
        NetClass net_class{NetClass::Lan};

        /// 网络能力归一化分 [0,1]（带宽越高/RTT 越低/丢包越少 分越高）
        float normalized_score() const noexcept;
    } network;

    // ------------------------------------------------------------------
    // 维度 3：稳定性
    // ------------------------------------------------------------------
    struct StabilityCap {
        float score{0.0f};              // 综合稳定性分 [0,1]（由下方公式计算）
        std::uint32_t uptime_seconds{0};     // 累计在线时长（秒）
        std::uint32_t disconnect_count{0};   // 24h 断连次数
        float task_success_rate{0.0f};       // 任务成功率 [0,1]
        TimePoint last_updated;

        /// 稳定性评分公式：
        ///   0.4 * (1 - min(disconnect_count/24, 1))
        /// + 0.3 * task_success_rate
        /// + 0.3 * min(uptime_seconds/86400, 1)
        /// 结果裁剪到 [0,1]
        static float compute_score(std::uint32_t uptime_seconds,
                                   std::uint32_t disconnect_count,
                                   float task_success_rate) noexcept;

        /// 刷新 score 字段（依据其他字段重算）
        void refresh_score() noexcept;

    } stability;

    // ------------------------------------------------------------------
    // 维度 4：地理
    // ------------------------------------------------------------------
    struct GeoCap {
        GeoRegion region{GeoRegion::Unknown};  // 华北/华东/...
        std::string city;                      // 城市
        std::string isp;                       // 运营商

        /// 地理维度归一化分 [0,1]（已知区域 1.0，Unknown 0.3）
        float normalized_score() const noexcept;
    } geo;

    // ------------------------------------------------------------------
    // 综合评分
    // ------------------------------------------------------------------

    /// 综合评分 [0,1]（默认权重）
    ///   = w_compute   * compute.normalized_score()
    ///   + w_network   * network.normalized_score()
    ///   + w_stability * stability.score
    ///   + w_geo       * geo.normalized_score()
    float overall_score() const noexcept;

    /// 带自定义权重的综合评分
    float overall_score(const NodeScoreWeights &w) const noexcept;

    /// 简要描述（日志用）
    std::string brief() const;
};

// ============================================================================
// NodeProfileStore — 线程安全的节点画像存储
// ============================================================================

/// 节点画像存储（线程安全，支持文本持久化）
///
/// 用法：
///   NodeProfileStore store;
///   store.upsert(profile);
///   auto p = store.get(endpoint_id);
///   store.save_to_file("linoh_profile.cache");
class NodeProfileStore {
public:
    NodeProfileStore() = default;

    // 不可拷贝、不可移动（含 mutex 不可移动成员）
    NodeProfileStore(const NodeProfileStore &) = delete;
    NodeProfileStore &operator=(const NodeProfileStore &) = delete;
    NodeProfileStore(NodeProfileStore &&) = delete;
    NodeProfileStore &operator=(NodeProfileStore &&) = delete;

    /// 插入或更新（按 endpoint_id 去重）
    void upsert(const NodeProfile &profile);

    /// 查询（不存在返回 nullopt）
    std::optional<NodeProfile> get(const base::EndpointId &id) const;

    /// 删除（返回是否实际删除）
    bool erase(const base::EndpointId &id);

    /// 当前条目数
    std::size_t size() const noexcept;

    /// 清空
    void clear() noexcept;

    /// 获取全部画像（快照拷贝）
    std::vector<NodeProfile> snapshot() const;

    /// 按 overall_score 降序返回前 N 个节点（调度器选节点用）
    std::vector<NodeProfile> top_n(std::size_t n,
                                    const NodeScoreWeights &w = {}) const;

    // ------------------------------------------------------------------
    // 文本持久化（INI 风格，每节点一个 [section]）
    // ------------------------------------------------------------------

    /// 保存到文件（覆盖写）。失败返回 false。
    bool save_to_file(const std::string &path) const;

    /// 从文件加载（清空当前内容后加载）。失败返回 false。
    bool load_from_file(const std::string &path);

private:
    mutable std::mutex mu_;
    std::unordered_map<base::EndpointId, NodeProfile> profiles_;
};

}  // namespace linoh
