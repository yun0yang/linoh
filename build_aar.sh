#!/usr/bin/env bash
# ============================================================================
#  linoh Android JNI .so 编译脚本（阶段 B：JNI 桥接验证）
#
#  用途：在 Linux host 上用 NDK r27d 编译 linoh 静态库 + JNI 桥接层
#        产出 liblinoh_jni.so（双 ABI: arm64-v8a + x86_64）
#
#  注意：本脚本仅验证 .so 编译通过，AAR 打包留给 Android Studio
#       （用户在 AS 中打开 android/ Module 即可通过 AGP 自动编译 .so + 打包 AAR）
#
#  用法：
#    export ANDROID_NDK_HOME=/path/to/ndk/27.3.13750724
#    ./build_aar.sh              # 编译全部 ABI
#    ./build_aar.sh arm64-v8a    # 仅编译 ARM64
#    ./build_aar.sh x86_64       # 仅编译 x86_64
#
#  前置：
#    - NDK r27d (LTS) 已安装
#    - CMake >= 3.22.1
#    - Ninja（可选，但推荐）
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

# ----------------------------------------------------------------------------
# 配置
# ----------------------------------------------------------------------------
NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${NDK_HOME:-}}}"
ABI_TARGET="${1:-all}"
MIN_SDK_VERSION=30
SUPPORTED_ABIS=("arm64-v8a" "x86_64")

if [ -t 1 ]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; NC=''
fi

log()  { printf '%s\n' "$*"; }
ok()   { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
err()  { printf "${RED}[ERR]${NC} %s\n" "$*" >&2; }

# ----------------------------------------------------------------------------
# 参数校验
# ----------------------------------------------------------------------------
if [ -z "$NDK_HOME" ]; then
    err "ANDROID_NDK_HOME 未设置。请先 export ANDROID_NDK_HOME=/path/to/ndk"
    err "推荐版本：NDK r27d (27.3.13750724)"
    exit 1
fi

if [ ! -d "$NDK_HOME" ]; then
    err "NDK 目录不存在：$NDK_HOME"
    exit 1
fi

TOOLCHAIN_FILE="$NDK_HOME/build/cmake/android.toolchain.cmake"
if [ ! -f "$TOOLCHAIN_FILE" ]; then
    err "找不到工具链文件：$TOOLCHAIN_FILE"
    exit 1
fi

if ! command -v cmake >/dev/null 2>&1; then
    err "未找到 cmake，请安装 CMake >= 3.22.1"
    exit 1
fi

USE_NINJA="no"
if command -v ninja >/dev/null 2>&1; then
    USE_NINJA="yes"
fi

JNI_SOURCE_DIR="$PWD/android/src/main/cpp"
if [ ! -f "$JNI_SOURCE_DIR/CMakeLists.txt" ]; then
    err "找不到 JNI 源码：$JNI_SOURCE_DIR/CMakeLists.txt"
    err "请确认 android/ Module 骨架已创建"
    exit 1
fi

# ----------------------------------------------------------------------------
# 步骤 1：编译 linoh 静态库（复用 build_android.sh）
# ----------------------------------------------------------------------------
log ""
log "============================================================"
log "  步骤 1/2: 编译 linoh 静态库（4 个 .a）"
log "============================================================"

# 调用 build_android.sh 编译所需 ABI
case "$ABI_TARGET" in
    arm64-v8a|x86_64)
        ./build_android.sh "$ABI_TARGET"
        ;;
    all)
        ./build_android.sh all
        ;;
    *)
        err "不支持的 ABI：$ABI_TARGET"
        err "支持的值：${SUPPORTED_ABIS[*]} 或 all"
        exit 1
        ;;
esac

# ----------------------------------------------------------------------------
# 步骤 2：编译 liblinoh_jni.so
# ----------------------------------------------------------------------------
build_jni_one_abi() {
    local abi="$1"
    local prebuilt_dir="$PWD/build/android/$abi/install"
    local build_dir="build/android-jni/$abi"

    log ""
    log "============================================================"
    log "  步骤 2: 编译 liblinoh_jni.so (ABI=$abi)"
    log "  预编译 .a 目录: $prebuilt_dir"
    log "  构建目录:       $build_dir"
    log "============================================================"

    # 校验 4 个 .a 文件存在
    local missing=0
    for lib in liblinoh.a liblinoh-relay.a liblinoh-base.a liblinoh-dns-server.a; do
        if [ ! -f "$prebuilt_dir/lib/$lib" ]; then
            err "缺少静态库：$prebuilt_dir/lib/$lib"
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
        err "预编译 .a 不完整，请先运行 ./build_android.sh $abi"
        exit 1
    fi

    mkdir -p "$build_dir"

    local cmake_args=(
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE"
        -DANDROID_ABI="$abi"
        -DANDROID_PLATFORM="android-$MIN_SDK_VERSION"
        -DANDROID_STL="c++_shared"
        -DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON
        -DCMAKE_BUILD_TYPE=Release
        -DLINOH_PREBUILT_DIR="$prebuilt_dir"
    )

    if [ "$USE_NINJA" = "yes" ]; then
        cmake_args+=(-G Ninja)
    fi

    log "CMake 配置中..."
    if ! cmake -S "$JNI_SOURCE_DIR" -B "$build_dir" "${cmake_args[@]}" 2>&1 | tee "$build_dir/cmake_configure.log" | tail -20; then
        err "CMake 配置失败（JNI, ABI=$abi）"
        err "完整日志：$build_dir/cmake_configure.log"
        exit 1
    fi

    log "编译 liblinoh_jni.so ..."
    local parallel=$(nproc 2>/dev/null || echo 4)
    if ! cmake --build "$build_dir" --parallel "$parallel" 2>&1 | tee "$build_dir/cmake_build.log" | tail -30; then
        err "JNI 编译失败（ABI=$abi）"
        err "完整日志：$build_dir/cmake_build.log"
        err "常见错误："
        err "  1. Kotlin 类未找到 → native 方法签名不匹配"
        err "  2. linoh_c.h 找不到 → 检查 LINOH_PREBUILT_DIR 路径"
        err "  3. 链接错误 → 4 个 .a 顺序必须为 linoh → relay → base → dns-server"
        exit 1
    fi

    # 验证产物
    local so_file="$build_dir/liblinoh_jni.so"
    if [ ! -f "$so_file" ]; then
        # 部分生成器把 .so 放在子目录
        so_file=$(find "$build_dir" -name "liblinoh_jni.so" -type f | head -1)
    fi

    if [ -z "$so_file" ] || [ ! -f "$so_file" ]; then
        err "未生成 liblinoh_jni.so (ABI=$abi)"
        exit 1
    fi

    log ""
    log "产物："
    ls -lh "$so_file" | sed 's/^/  /'

    # 架构验证
    if command -v file >/dev/null 2>&1; then
        log ""
        log "架构验证："
        file "$so_file" | sed 's/^/  /'
    fi

    # 符号验证：检查 JNI 入口符号
    if command -v nm >/dev/null 2>&1; then
        log ""
        log "JNI 入口符号（应能看到 Java_com_linoh_android_*）："
        nm -D "$so_file" 2>/dev/null | grep -E 'Java_com_linoh_android_' | head -10 | sed 's/^/  /'
        local sym_count=$(nm -D "$so_file" 2>/dev/null | grep -c -E 'Java_com_linoh_android_')
        log "  JNI 入口符号总数：$sym_count"
        if [ "$sym_count" -lt 20 ]; then
            warn "JNI 入口符号数量偏少（<20），检查是否所有 native 方法都被导出"
        fi
    fi

    # 16KiB page size 验证（Android 15+ 必需）
    if command -v readelf >/dev/null 2>&1; then
        log ""
        log "ELF 头部验证（max-page-size 应为 16384）："
        readelf -l "$so_file" 2>/dev/null | grep -E 'LOAD' | head -2 | sed 's/^/  /'
        local align=$(readelf -lW "$so_file" 2>/dev/null | awk '/LOAD/{print $0; exit}' | awk '{print $NF}')
        log "  对齐值：$align"
    fi

    ok "ABI $abi JNI 编译完成：$so_file"
}

# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------
log ""
log "============================================================"
log "  linoh Android JNI .so 编译（阶段 B：JNI 桥接验证）"
log "============================================================"
log "NDK 路径:        $NDK_HOME"
log "工具链文件:      $TOOLCHAIN_FILE"
log "minSdkVersion:   $MIN_SDK_VERSION (Android 11.0+)"
log "JNI 源码目录:    $JNI_SOURCE_DIR"
log "目标 ABI:        $ABI_TARGET"
log ""

case "$ABI_TARGET" in
    arm64-v8a|x86_64)
        build_jni_one_abi "$ABI_TARGET"
        ;;
    all)
        for abi in "${SUPPORTED_ABIS[@]}"; do
            build_jni_one_abi "$abi"
        done
        ;;
esac

log ""
log "============================================================"
ok "阶段 B JNI .so 编译完成"
log "============================================================"
log ""
log "产物路径："
log "  build/android-jni/<abi>/liblinoh_jni.so"
log ""
log "下一步建议："
log "  1. 在 Android Studio 中打开 linoh/android/ Module"
log "  2. 通过 -PlinohPrebuiltDir=<path> 指定 .a 路径（默认 ../build/android/\${ABI}/install）"
log "  3. 执行 assembleRelease 产出 AAR"
log "  4. AAR 内含 jni/<abi>/liblinoh_jni.so + Kotlin 类 + consumer-rules.pro"
