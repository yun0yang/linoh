// linoh/util/crc32.hpp — IEEE 802.3 CRC32（用于密钥文件完整性校验）
//
// 多项式：0xEDB88320（反射形式）
// 初始值：0xFFFFFFFF，输出异或 0xFFFFFFFF
// 与 zlib/PNG 标准 CRC32 一致
//
// 设计要点：
//   1. 查表法（256 项表），启动时一次性初始化（线程安全 static 局部变量）
//   2. 头文件 inline 实现，无额外链接负担
//   3. 用于 linoh 密钥文件持久化的 CRC32 校验字段（见 §3.1 文件格式）

#pragma once

#include <cstdint>
#include <span>

namespace linoh::util {

/// 计算 IEEE 802.3 CRC32
/// @param data 输入字节
/// @return CRC32 校验值（已异或 0xFFFFFFFF）
/// @note 首次调用会初始化 256 项查表（线程安全）
uint32_t crc32_ieee(std::span<const uint8_t> data);

/// 增量 CRC32 计算（用于分块流式校验）
/// @param prev 上一次的 CRC 值（首次传 0）
/// @param data 本块数据
/// @return 更新后的 CRC 值（最终结果需异或 0xFFFFFFFF）
/// @note 内部使用，外部一般直接用 crc32_ieee
uint32_t crc32_ieee_update(uint32_t prev, std::span<const uint8_t> data);

} // namespace linoh::util
