// geo_region.hpp — 地理区域定义（v2.0 Phase 1）
//
// 从 nat/relay_pool.hpp 提取到 linoh 顶层，解耦 NodeProfile 等上层模块
// 对 nat 层的依赖。GeoRegion 是跨层共享的基础枚举类型。
//
// 用于：
//   - RelayPool 地理感知 Relay 选择（nat 层）
//   - NodeProfile 节点地理画像（profile 层）
//   - 控制面分层 gossip 区域聚合（control 层）

#pragma once

#include <cstdint>
#include <string>

namespace linoh {

// ============================================================================
// 地理区域（中国七大地理分区 + 全国骨干 + 未知）
// ============================================================================

enum class GeoRegion : std::uint8_t {
    Unknown,    // 未指定（向后兼容）
    North,      // 华北（北京/天津/河北/山西/内蒙古）
    East,       // 华东（上海/江苏/浙江/安徽/福建/江西/山东）
    South,      // 华南（广东/广西/海南）
    Central,    // 华中（河南/湖北/湖南）
    Southwest,  // 西南（重庆/四川/贵州/云南/西藏）
    Northwest,  // 西北（陕西/甘肃/青海/宁夏/新疆）
    Northeast,  // 东北（辽宁/吉林/黑龙江）
    Backbone,   // 全国骨干 Relay（仅承担跨区域中转）
};

/// 地理区域转字符串
constexpr const char *geo_region_name(GeoRegion r) {
    switch (r) {
        case GeoRegion::Unknown:    return "unknown";
        case GeoRegion::North:      return "north";
        case GeoRegion::East:       return "east";
        case GeoRegion::South:      return "south";
        case GeoRegion::Central:    return "central";
        case GeoRegion::Southwest:  return "southwest";
        case GeoRegion::Northwest:  return "northwest";
        case GeoRegion::Northeast:  return "northeast";
        case GeoRegion::Backbone:   return "backbone";
    }
    return "unknown";
}

/// 从字符串解析地理区域（持久化/配置解析用）
inline GeoRegion geo_region_from_name(const std::string &name) {
    if (name == "north")      return GeoRegion::North;
    if (name == "east")       return GeoRegion::East;
    if (name == "south")      return GeoRegion::South;
    if (name == "central")    return GeoRegion::Central;
    if (name == "southwest")  return GeoRegion::Southwest;
    if (name == "northwest")  return GeoRegion::Northwest;
    if (name == "northeast")  return GeoRegion::Northeast;
    if (name == "backbone")   return GeoRegion::Backbone;
    return GeoRegion::Unknown;
}

/// 判断两个区域是否视为"跨区域"（Backbone 与任意区域都不算跨区域，
/// 因为骨干 Relay 设计上服务全国）
constexpr bool is_cross_region(GeoRegion local, GeoRegion relay) {
    if (local == GeoRegion::Unknown || relay == GeoRegion::Unknown) return false;
    if (local == GeoRegion::Backbone || relay == GeoRegion::Backbone) return false;
    return local != relay;
}

}  // namespace linoh
