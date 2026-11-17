#!/usr/bin/env bash
# ============================================================================
#  linoh Android NDK 交叉编译脚本（阶段 A：host 验证）
#
#  用途：在 Linux host 上用 NDK r27d 交叉编译 linoh 核心库为 ARM64/x86_64 静态库
#        验证 C++20 / std::span / POSIX API 在 Android Bionic libc 下编译通过
#
#  用法：
#    export ANDROID_NDK_HOME=/path/to/ndk/27.3.13750724
#    ./build_android.sh arm64-v8a    # 构建 ARM64（生产）
#    ./build_android.sh x86_64       # 构建 x86_64（模拟器开发）
#    ./build_android.sh all          # 构建全部 ABI
#
#  前置：
#    - NDK r27d (LTS) 已安装
#    - CMake >= 3.22.1
#    - Ninja
#    - 不修改 linoh 源码（验证阶段）
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

# ----------------------------------------------------------------------------
# 配置
# ----------------------------------------------------------------------------
NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${NDK_HOME:-}}}"
ABI="${1:-arm64-v8a}"
MIN_SDK_VERSION=30              # Android 11.0+，用户确认
CMAKE_MIN_VERSION="3.22.1"

# 支持的 ABI 列表
SUPPORTED_ABIS=("arm64-v8a" "x86_64")

# 颜色输出（可选）
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
    err "下载：https://developer.android.com/ndk/downloads"
    exit 1
fi

if [ ! -d "$NDK_HOME" ]; then
    err "NDK 目录不存在：$NDK_HOME"
    exit 1
fi

TOOLCHAIN_FILE="$NDK_HOME/build/cmake/android.toolchain.cmake"
if [ ! -f "$TOOLCHAIN_FILE" ]; then
    err "找不到工具链文件：$TOOLCHAIN_FILE"
    err "请确认 NDK 安装完整"
    exit 1
fi

# 校验 NDK 版本（粗略检查 source.properties）
NDK_VERSION_FILE="$NDK_HOME/source.properties"
if [ -f "$NDK_VERSION_FILE" ]; then
    NDK_VERSION=$(grep -E '^Pkg\.Revision' "$NDK_VERSION_FILE" | cut -d'=' -f2 | tr -d ' ')
    log "检测到 NDK 版本：$NDK_VERSION"
    # 提取主版本号
    NDK_MAJOR=$(echo "$NDK_VERSION" | cut -d'.' -f1)
    if [ "$NDK_MAJOR" -lt 27 ]; then
        warn "NDK 版本过低（r$NDK_MAJOR），推荐 r27d+ 以获得完整 C++20 支持"
        warn "继续编译但可能遇到 std::span 等问题"
    fi
fi

# 校验 CMake
if ! command -v cmake >/dev/null 2>&1; then
    err "未找到 cmake，请安装 CMake >= $CMAKE_MIN_VERSION"
    exit 1
fi
CMAKE_VERSION=$(cmake --version | head -1 | awk '{print $3}')
log "检测到 CMake 版本：$CMAKE_VERSION"

# 校验 Ninja
USE_NINJA="no"
if command -v ninja >/dev/null 2>&1; then
    USE_NINJA="yes"
    log "检测到 Ninja，将使用 Ninja 生成器（推荐）"
else
    warn "未找到 Ninja，将使用 Make 生成器（速度较慢）"
fi

# ----------------------------------------------------------------------------
# 单 ABI 构建函数
# ----------------------------------------------------------------------------
build_one_abi() {
    local abi="$1"
    local build_dir="build/android/$abi"
    local install_dir="build/android/$abi/install"

    log ""
    log "============================================================"
    log "  构建 ABI: $abi"
    log "  minSdkVersion: $MIN_SDK_VERSION"
    log "  输出目录: $install_dir"
    log "============================================================"

    mkdir -p "$build_dir"

    # CMake 参数
    local cmake_args=(
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE"
        -DANDROID_ABI="$abi"
        -DANDROID_PLATFORM="android-$MIN_SDK_VERSION"
        -DANDROID_STL="c++_shared"
        -DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_INSTALL_PREFIX="$install_dir"
        -DLINOH_BUILD_SERVERS=OFF
        -DLINOH_BUILD_TOOLS=OFF
        -DLINOH_BUILD_TESTS=OFF
        -DLINOH_BUILD_EXAMPLES=OFF
    )

    if [ "$USE_NINJA" = "yes" ]; then
        cmake_args+=(-G Ninja)
    fi

    log "CMake 配置中..."
    if ! cmake -S . -B "$build_dir" "${cmake_args[@]}" 2>&1 | tee "$build_dir/cmake_configure.log" | tail -20; then
        err "CMake 配置失败（ABI=$abi）"
        err "完整日志：$build_dir/cmake_configure.log"
        exit 1
    fi

    log "编译中（可能需要几分钟）..."
    local parallel=$(nproc 2>/dev/null || echo 4)
    if ! cmake --build "$build_dir" --parallel "$parallel" 2>&1 | tee "$build_dir/cmake_build.log" | tail -30; then
        err "编译失败（ABI=$abi）"
        err "完整日志：$build_dir/cmake_build.log"
        err "常见错误："
        err "  1. std::span 未找到 → 检查 NDK 版本 >= r27d"
        err "  2. pthread_cancel 未定义 → 需改写为 cooperative cancellation"
        err "  3. std::format 未实现 → r27d 部分支持，避免使用"
        exit 1
    fi

    log "安装到 $install_dir ..."
    cmake --install "$build_dir" 2>&1 | tail -5

    # 验证产物
    log ""
    log "产物清单："
    if [ -d "$install_dir/lib" ]; then
        ls -lh "$install_dir/lib"/liblinoh*.a 2>/dev/null || warn "未找到 .a 文件"
    else
        warn "install_dir/lib 不存在"
    fi

    # file 命令验证架构
    if command -v file >/dev/null 2>&1; then
        log ""
        log "架构验证（file 命令）："
        # 临时关闭 pipefail 和 errexit，避免：
        #   1. `ar t | head -1` 触发 SIGPIPE（pipefail）
        #   2. `ar x` 在 cd tmp_dir 后用相对路径找不到 .a 文件返回非 0（errexit）
        set +o pipefail
        set +e
        for lib in "$install_dir/lib"/liblinoh*.a; do
            [ -f "$lib" ] || continue
            # .a 是归档，用 ar 提取首个 .o 再 file
            local first_obj=$(ar t "$lib" 2>/dev/null | head -1)
            if [ -n "$first_obj" ]; then
                # 转成绝对路径，避免 cd tmp_dir 后相对路径失效
                local lib_abs="$(cd "$(dirname "$lib")" && pwd)/$(basename "$lib")"
                local tmp_dir=$(mktemp -d)
                (cd "$tmp_dir" && ar x "$lib_abs" "$first_obj" 2>/dev/null)
                if [ -f "$tmp_dir/$first_obj" ]; then
                    file "$tmp_dir/$first_obj" 2>/dev/null | sed 's/^/  /'
                fi
                rm -rf "$tmp_dir"
            fi
        done
        set -e
        set -o pipefail
    fi

    ok "ABI $abi 构建完成"
}

# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------
log "============================================================"
log "  linoh Android NDK 交叉编译（阶段 A：host 验证）"
log "============================================================"
log "NDK 路径:        $NDK_HOME"
log "工具链文件:      $TOOLCHAIN_FILE"
log "minSdkVersion:   $MIN_SDK_VERSION (Android 11.0+)"
log "C++ STL:         c++_shared"
log "16KiB page size: 已开启"
log ""

case "$ABI" in
    arm64-v8a|x86_64)
        build_one_abi "$ABI"
        ;;
    all)
        warn "将构建全部 ABI：${SUPPORTED_ABIS[*]}"
        for abi in "${SUPPORTED_ABIS[@]}"; do
            build_one_abi "$abi"
        done
        ;;
    *)
        err "不支持的 ABI：$ABI"
        err "支持的 ABI：${SUPPORTED_ABIS[*]} 或 all"
        exit 1
        ;;
esac

log ""
log "============================================================"
ok "阶段 A 验证完成"
log "============================================================"
log ""
log "下一步建议："
log "  1. 检查 build/android/<abi>/install/lib/ 下的 4 个 .a 文件"
log "  2. 用 nm 命令验证关键符号导出："
log "     nm build/android/arm64-v8a/install/lib/liblinoh.a | grep linoh_endpoint"
log "  3. 如编译失败，把 build/android/<abi>/cmake_build.log 发回分析"
log "  4. 编译通过后进入阶段 B（Android Library Module + JNI 桥接层）"
