#!/usr/bin/env bash
# Native MSVC build without cmd.exe — sets INCLUDE/LIB/PATH and calls cl/lib/link directly.
set -u

VSROOT="/c/Program Files/Microsoft Visual Studio/2022/Community"
VC="$VSROOT/VC/Tools/MSVC/14.44.35207"
SDK="/c/Program Files (x86)/Windows Kits/10"
SDKVER="10.0.26100.0"
BINDIR="$VC/bin/Hostx64/x64"

export PATH="$BINDIR:$PATH"
export INCLUDE="$(cygpath -w "$VC/include");$(cygpath -w "$SDK/Include/$SDKVER/ucrt");$(cygpath -w "$SDK/Include/$SDKVER/um");$(cygpath -w "$SDK/Include/$SDKVER/shared");$(cygpath -w "$SDK/Include/$SDKVER/winrt")"
export LIB="$(cygpath -w "$VC/lib/x64");$(cygpath -w "$SDK/Lib/$SDKVER/ucrt/x64");$(cygpath -w "$SDK/Lib/$SDKVER/um/x64")"

CL="$BINDIR/cl.exe"
LIBTOOL="$BINDIR/lib.exe"
LINK="$BINDIR/link.exe"

log() { printf '%s\n' "$1"; }

# Mode:  ${1:-} = "nosan" (Release) or anything else (ASan).
# TLS:   ${2:-} = "relaytls" enables the optional OpenSSL-backed wss:// backend.
# Bench: ${2:-} = "bench"   builds all bench_*.exe (Release /O2, no ASan, no TLS).
RELAY_TLS=0
if [ "${2:-}" = "relaytls" ]; then RELAY_TLS=1; fi

BASE_CXXFLAGS=""
if [ "${1:-}" = "nosan" ]; then
  BASE_CXXFLAGS="/std:c++20 /EHsc /permissive- /O2 /utf-8"
  log "mode: Release (no ASan)"
else
  BASE_CXXFLAGS="/std:c++20 /EHsc /permissive- /O2 /utf-8 /fsanitize=address"
  log "mode: ASan"
fi

if [ "$RELAY_TLS" = "1" ]; then
  log "relay TLS backend: ENABLED (OpenSSL via conda)"
  OPENSSL_INC="$(cygpath -w /c/ProgramData/miniconda3/Library/include)"
  OPENSSL_LIB="$(cygpath -w /c/ProgramData/miniconda3/Library/lib)"
  export INCLUDE="$OPENSSL_INC;$INCLUDE"
  export LIB="$OPENSSL_LIB;$LIB"
  OPENSSL_LIBS="libssl.lib libcrypto.lib crypt32.lib"
  # IMPORTANT: conda's OpenSSL include is placed FIRST and third_party/openssl
  # (stub headers) is omitted, so the real OpenSSL headers win unambiguously.
  CXXFLAGS="$BASE_CXXFLAGS -DLINOH_RELAY_TLS /I$OPENSSL_INC /I. /Iinclude /Ithird_party/asio/include"
else
  log "relay TLS backend: disabled (default; plain ws://)"
  OPENSSL_LIBS=""
  CXXFLAGS="$BASE_CXXFLAGS /I. /Iinclude /Ithird_party/asio/include /Ithird_party/openssl/include"
fi

PROJ="$(cygpath -w "$PWD")"

mkdir -p build

# tls_channel.cpp is always compiled. When TLS is OFF it is a transparent
# recv/send passthrough; when ON it is the real OpenSSL backend.
COMMON_SRCS=(
  src/endpoint/builder.cpp
  src/endpoint/connection.cpp
  src/endpoint/endpoint.cpp
  src/net/socket.cpp
  src/net/udp_transport.cpp
  src/protocol/packet.cpp
  src/protocol/router.cpp
  src/protocol/ack.cpp
  src/protocol/loss_recovery.cpp
  src/protocol/flow_control.cpp
  src/protocol/path_migration.cpp
  src/tls/crypto_provider.cpp
  src/tls/ed25519_core.cpp
  src/tls/ed25519_verifier.cpp
  src/tls/handshake_token_key.cpp
  src/crypto/x25519.cpp
  src/crypto/hkdf.cpp
  src/base/key.cpp
  src/base/endpoint_addr.cpp
  src/util/crypto.cpp
  src/address_lookup/pkarr_publisher.cpp
  src/address_lookup/pkarr_server.cpp
  src/relay/client.cpp
  src/relay/server.cpp
  src/relay/tls_channel.cpp
  src/linoh_c.cpp
)

if [ "$RELAY_TLS" = "1" ]; then
  # Real OpenSSL provides EVP/etc., so the stub is dropped (avoids duplicate
  # EVP_* symbols at link time).
  SRCS=("${COMMON_SRCS[@]}")
else
  SRCS=("${COMMON_SRCS[@]}" third_party/openssl/src/evp_stub.cpp)
fi

OBJS=()
for f in "${SRCS[@]}"; do
  base="${f##*/}"
  obj="build/${base%.cpp}.obj"
  log "compile $f"
  "$CL" $CXXFLAGS "$(cygpath -w "$f")" /c "/Fo:$(cygpath -w "$obj")" || { echo "FAILED: $f"; exit 1; }
  OBJS+=("$(cygpath -w "$obj")")
done

log "link linoh.lib"
"$LIBTOOL" /NOLOGO "/OUT:$(cygpath -w build/linoh.lib)" "${OBJS[@]}" || { echo "LIB FAILED"; exit 1; }

if [ "$RELAY_TLS" = "1" ]; then
  # Make the OpenSSL DLLs available next to the test executables at runtime.
  cp "$(cygpath -w /c/ProgramData/miniconda3/Library/bin/libssl-3-x64.dll)" build/ 2>/dev/null || true
  cp "$(cygpath -w /c/ProgramData/miniconda3/Library/bin/libcrypto-3-x64.dll)" build/ 2>/dev/null || true
fi

# Tests
build_test() {
  local src="$1" objname="$2" out="$3"
  log "compile+link tests/$src"
  "$CL" $CXXFLAGS "$(cygpath -w "tests/$src")" /c "/Fo:$(cygpath -w "build/$objname")" || { echo "TEST COMPILE FAILED"; exit 1; }
  "$LINK" /NOLOGO "/OUT:$(cygpath -w "build/$out")" "$(cygpath -w "build/$objname")" "$(cygpath -w build/linoh.lib)" ws2_32.lib user32.lib bcrypt.lib $OPENSSL_LIBS /SUBSYSTEM:CONSOLE || { echo "TEST LINK FAILED"; exit 1; }
}

build_test test_relay_server.cpp test_relay_server.obj test_relay_server.exe
build_test test_phase4_integration.cpp test_phase4.obj test_phase4.exe
build_test test_state_machine.cpp test_state_machine.obj test_state_machine.exe
build_test test_x25519_hkdf.cpp test_x25519_hkdf.obj test_x25519_hkdf.exe
build_test test_key_schedule.cpp test_key_schedule.obj test_key_schedule.exe
build_test test_handshake_msg.cpp test_handshake_msg.obj test_handshake_msg.exe
build_test test_tls13_handshake.cpp test_tls13_handshake.obj test_tls13_handshake.exe
build_test test_connection_tls13.cpp test_connection_tls13.obj test_connection_tls13.exe
build_test test_endpoint_tls13.cpp test_endpoint_tls13.obj test_endpoint_tls13.exe
build_test test_pkarr_server.cpp test_pkarr_server.obj test_pkarr_server.exe
build_test test_integration_e2e.cpp test_integration_e2e.obj test_integration_e2e.exe

# ─── 性能基准（bench 模式）─────────────────────────────────────────────────
# Mode:  ${2:-} = "bench" 构建所有 bench_*.exe（Release /O2，无 ASan）
#        （bench 与 relaytls 互斥；bench 优先）
BUILD_BENCH=0
if [ "${2:-}" = "bench" ]; then BUILD_BENCH=1; fi

if [ "$BUILD_BENCH" = "1" ]; then
  log "mode: BENCHMARK (Release /O2, no ASan)"

  # 强制 Release 模式（基准必须无 ASan，避免性能偏差）
  BENCH_CXXFLAGS="/std:c++20 /EHsc /permissive- /O2 /utf-8 /I. /Iinclude /Ithird_party/asio/include"

  build_bench() {
    local src="$1" objname="$2" out="$3"
    log "compile+link tests/$src (bench)"
    "$CL" $BENCH_CXXFLAGS "$(cygpath -w "tests/$src")" /c "/Fo:$(cygpath -w "build/$objname")" || { echo "BENCH COMPILE FAILED: $src"; exit 1; }
    "$LINK" /NOLOGO "/OUT:$(cygpath -w "build/$out")" "$(cygpath -w "build/$objname")" "$(cygpath -w build/linoh.lib)" ws2_32.lib user32.lib bcrypt.lib $OPENSSL_LIBS /SUBSYSTEM:CONSOLE || { echo "BENCH LINK FAILED: $src"; exit 1; }
  }

  # 重新构建 Release 版本的 linoh.lib（无 ASan）
  log "rebuild linoh.lib in Release mode (no ASan) for benchmark"
  BENCH_OBJS=()
  for f in "${SRCS[@]}"; do
    base="${f##*/}"
    obj="build/bench_${base%.cpp}.obj"
    "$CL" $BENCH_CXXFLAGS "$(cygpath -w "$f")" /c "/Fo:$(cygpath -w "$obj")" || { echo "FAILED: $f"; exit 1; }
    BENCH_OBJS+=("$(cygpath -w "$obj")")
  done
  "$LIBTOOL" /NOLOGO "/OUT:$(cygpath -w build/linoh_bench.lib)" "${BENCH_OBJS[@]}" || { echo "BENCH LIB FAILED"; exit 1; }

  # 重新链接 bench 用 Release linoh_bench.lib
  build_bench_release() {
    local src="$1" objname="$2" out="$3"
    log "compile+link tests/$src (bench release)"
    "$CL" $BENCH_CXXFLAGS "$(cygpath -w "tests/$src")" /c "/Fo:$(cygpath -w "build/$objname")" || { echo "BENCH COMPILE FAILED: $src"; exit 1; }
    "$LINK" /NOLOGO "/OUT:$(cygpath -w "build/$out")" "$(cygpath -w "build/$objname")" "$(cygpath -w build/linoh_bench.lib)" ws2_32.lib user32.lib bcrypt.lib $OPENSSL_LIBS /SUBSYSTEM:CONSOLE || { echo "BENCH LINK FAILED: $src"; exit 1; }
  }

  build_bench_release bench_handshake.cpp bench_handshake.obj bench_handshake.exe
  build_bench_release bench_throughput.cpp bench_throughput.obj bench_throughput.exe
  build_bench_release bench_rtt.cpp bench_rtt.obj bench_rtt.exe
  build_bench_release bench_concurrency.cpp bench_concurrency.obj bench_concurrency.exe

  log "BENCH BUILD OK — run with: build/bench_handshake.exe / bench_throughput.exe / bench_rtt.exe / bench_concurrency.exe"
fi

log "BUILD OK"
