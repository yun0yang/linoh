// linoh/util/crc32.cpp — IEEE 802.3 CRC32 查表实现
//
// 多项式：0xEDB88320（反射形式），与 zlib/PNG 一致
// 初始值 0xFFFFFFFF，输出异或 0xFFFFFFFF
//
// 线程安全：static 局部变量初始化由 C++11 标准保证线程安全

#include "linoh/util/crc32.hpp"

#include <array>

namespace linoh::util {

namespace {

/// 生成 CRC32 查表（256 项）
/// 多项式 0xEDB88320 是 0x04C11DB7 的反射形式
std::array<uint32_t, 256> make_crc_table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }
    return table;
}

/// 获取查表（首次调用初始化，线程安全）
const std::array<uint32_t, 256> &crc_table() {
    static const std::array<uint32_t, 256> table = make_crc_table();
    return table;
}

} // namespace

uint32_t crc32_ieee_update(uint32_t prev, std::span<const uint8_t> data) {
    const auto &table = crc_table();
    uint32_t crc = prev ^ 0xFFFFFFFFU;
    for (uint8_t byte : data) {
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFU;
}

uint32_t crc32_ieee(std::span<const uint8_t> data) {
    // prev=0 → crc 初始 = 0 ^ 0xFFFFFFFF = 0xFFFFFFFF
    return crc32_ieee_update(0, data);
}

} // namespace linoh::util
