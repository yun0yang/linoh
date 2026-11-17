cmake_minimum_required(VERSION 3.22.1)
project(linoh_jni LANGUAGES CXX)

# ---------------------------------------------------------------------------
# C++ 标准：gnu++20（与 linoh 主项目一致，POSIX 扩展支持 pthread_*）
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 符号可见性：默认隐藏，仅 export JNI 入口（JNIEXPORT 自带 default visibility）
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

# ---------------------------------------------------------------------------
# linoh 预编译静态库路径
# 由 build.gradle.kts 通过 -DLINOH_PREBUILT_DIR=<path> 传入
# 期望目录结构（阶段 A install 产物）：
#   <LINOH_PREBUILT_DIR>/lib/liblinoh-base.a
#   <LINOH_PREBUILT_DIR>/lib/liblinoh.a
#   <LINOH_PREBUILT_DIR>/lib/liblinoh-relay.a
#   <LINOH_PREBUILT_DIR>/lib/liblinoh-dns-server.a
#   <LINOH_PREBUILT_DIR>/include/linoh/*.h*
# ---------------------------------------------------------------------------
if(NOT DEFINED LINOH_PREBUILT_DIR)
    message(FATAL_ERROR
        "LINOH_PREBUILT_DIR 未指定。请通过 -DLINOH_PREBUILT_DIR=<path> 提供 "
        "linoh 静态库预编译目录（来自 build_android.sh 产物的 install 目录）")
endif()

get_filename_component(LINOH_PREBUILT_DIR_ABS "${LINOH_PREBUILT_DIR}" ABSOLUTE)
message(STATUS "linoh prebuilt dir: ${LINOH_PREBUILT_DIR_ABS}")

set(LINOH_INCLUDE_DIR "${LINOH_PREBUILT_DIR_ABS}/include")
set(LINOH_LIB_DIR     "${LINOH_PREBUILT_DIR_ABS}/lib")

# 校验关键文件存在
foreach(lib_name
        liblinoh-base.a
        liblinoh.a
        liblinoh-relay.a
        liblinoh-dns-server.a)
    if(NOT EXISTS "${LINOH_LIB_DIR}/${lib_name}")
        message(FATAL_ERROR "linoh 静态库缺失: ${LINOH_LIB_DIR}/${lib_name}")
    endif()
endforeach()

if(NOT EXISTS "${LINOH_INCLUDE_DIR}/linoh/linoh_c.h")
    message(FATAL_ERROR "linoh_c.h 缺失: ${LINOH_INCLUDE_DIR}/linoh/linoh_c.h")
endif()

# ---------------------------------------------------------------------------
# JNI 源文件
# ---------------------------------------------------------------------------
add_library(linoh_jni SHARED
    linoh_jni.cpp
    jni_raii.cpp)

target_include_directories(linoh_jni PRIVATE
    ${LINOH_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

# ---------------------------------------------------------------------------
# 链接 linoh 静态库（顺序：jni → linoh → linoh-relay → linoh-base → dns-server）
# 注意：linoh.lib 依赖 linoh-base.lib；linoh-relay.lib 也依赖 linoh-base.lib
# Android log 库供 __android_log_print 使用
# ---------------------------------------------------------------------------
find_library(LOG_LIB log REQUIRED)

target_link_libraries(linoh_jni PRIVATE
    ${LINOH_LIB_DIR}/liblinoh.a
    ${LINOH_LIB_DIR}/liblinoh-relay.a
    ${LINOH_LIB_DIR}/liblinoh-base.a
    ${LINOH_LIB_DIR}/liblinoh-dns-server.a
    ${LOG_LIB})

# ---------------------------------------------------------------------------
# 16KiB page size 支持（Android 15+ 新设备必需）
# ---------------------------------------------------------------------------
target_link_options(linoh_jni PRIVATE -Wl,-z,max-page-size=16384)

# 平台标识
target_compile_definitions(linoh_jni PRIVATE LINOH_PLATFORM_ANDROID=1)

message(STATUS "linoh_jni 配置完成")
message(STATUS "  C++ Standard:       gnu++20")
message(STATUS "  ABI:                ${ANDROID_ABI}")
message(STATUS "  Symbol visibility:  hidden (JNI exports only)")
message(STATUS "  16KiB page size:    enabled")
