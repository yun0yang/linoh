#!/usr/bin/env bash
# ============================================================================
#  linoh Linux build script (mirror of build_all.bat)
#  Compiler: g++ (default) or clang++ via CXX env var
#  Output:   build/lib*.a + linoh-relay-server + linoh-dns-server +
#            linoh_relay_bridge + 54 test binaries
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build

CXX="${CXX:-g++}"
AR="${AR:-ar}"

# Compiler flags
CXXFLAGS="-std=c++20 -O2 -pthread -Wall -Wextra -Wno-unused-parameter \
    -DLINOH_USE_STUB_ASIO \
    -mavx2 -msse4.2 -mbmi2 \
    -I. -Iinclude -Ithird_party/asio/include -Ithird_party/openssl/include -Ithird_party/zstd"

# C compiler flags (for zstd C sources)
# -DZSTD_DISABLE_ASM: 禁用 zstd amd64 汇编优化（huf_decompress_amd64.S 未纳入源文件列表），
#   避免 HUF_decompress4X*_usingDTable_internal_fast_asm_loop 符号缺失导致链接失败
CFLAGS="-O2 -pthread -DZSTD_STATIC_LINKING_ONLY -DZSTD_LEGACY_SUPPORT=0 -DZSTD_DISABLE_ASM -Ithird_party/zstd"

# Linker flags
LDFLAGS="-pthread"

# Libraries
LIBS=""  # Linux 不需要 ws2_32/user32/bcrypt，POSIX socket/pthread/std::random_device 已覆盖

log() { printf '%s\n' "$*"; }

# Build a single .cpp into build/<objname>.o
# Usage: compile_one <src.cpp> <objname>
compile_one() {
    local src="$1" objname="$2" errfile="build/err_${objname}.txt"
    log "  compile $src"
    if ! $CXX $CXXFLAGS -c "$src" -o "build/${objname}.o" 2>"$errfile"; then
        log "FAILED: $src"
        cat "$errfile"
        exit 1
    fi
}

# Link a static library from a list of object files
# Usage: link_lib <libname> <obj1> <obj2> ...
link_lib() {
    local libname="$1"; shift
    local objs=()
    for o in "$@"; do objs+=("build/${o}.o"); done
    log "  link build/${libname}"
    $AR rcs "build/${libname}" "${objs[@]}"
}

# Link an executable from an object file + libraries
# Usage: link_exe <outname> <objname> <extra_libs...>
link_exe() {
    local out="$1" objname="$2"; shift 2
    log "  link build/${out}"
    if ! $CXX $LDFLAGS -o "build/${out}" "build/${objname}.o" "$@" $LIBS 2>build/err_link_${out}.txt; then
        log "FAILED: link $out"
        cat "build/err_link_${out}.txt"
        exit 1
    fi
}

# ============================================================================
# Crate zstd: vendored zstd 1.5.6 compression (C sources, V3.4)
# ============================================================================
log "============================================================"
log "  Building liblinoh_zstd.a  Crate 0: vendored zstd 1.5.6"
log "============================================================"

ZSTD_SRCS=(
    third_party/zstd/common/debug.c
    third_party/zstd/common/entropy_common.c
    third_party/zstd/common/error_private.c
    third_party/zstd/common/fse_decompress.c
    third_party/zstd/common/pool.c
    third_party/zstd/common/threading.c
    third_party/zstd/common/xxhash.c
    third_party/zstd/common/zstd_common.c
    third_party/zstd/compress/fse_compress.c
    third_party/zstd/compress/hist.c
    third_party/zstd/compress/huf_compress.c
    third_party/zstd/compress/zstdmt_compress.c
    third_party/zstd/compress/zstd_compress.c
    third_party/zstd/compress/zstd_compress_literals.c
    third_party/zstd/compress/zstd_compress_sequences.c
    third_party/zstd/compress/zstd_compress_superblock.c
    third_party/zstd/compress/zstd_double_fast.c
    third_party/zstd/compress/zstd_fast.c
    third_party/zstd/compress/zstd_lazy.c
    third_party/zstd/compress/zstd_ldm.c
    third_party/zstd/compress/zstd_opt.c
    third_party/zstd/decompress/huf_decompress.c
    third_party/zstd/decompress/zstd_ddict.c
    third_party/zstd/decompress/zstd_decompress.c
    third_party/zstd/decompress/zstd_decompress_block.c
    third_party/zstd/dictBuilder/cover.c
    third_party/zstd/dictBuilder/divsufsort.c
    third_party/zstd/dictBuilder/fastcover.c
    third_party/zstd/dictBuilder/zdict.c
)
ZSTD_OBJS=()
CC="${CC:-gcc}"
for f in "${ZSTD_SRCS[@]}"; do
    base=$(basename "$f" .c)
    objname="zstd_${base}"
    log "  compile $f"
    if ! $CC $CFLAGS -c "$f" -o "build/${objname}.o" 2>build/err_${objname}.txt; then
        log "FAILED: $f"
        cat "build/err_${objname}.txt"
        exit 1
    fi
    ZSTD_OBJS+=("$objname")
done
link_lib "liblinoh_zstd.a" "${ZSTD_OBJS[@]}"
log ""

# ============================================================================
# Crate 1: linoh-base  (base + crypto + tls + util)
# ============================================================================
log "============================================================"
log "  Building liblinoh-base.a  Crate 1: base + crypto + tls + util"
log "============================================================"

BASE_SRCS=(
    src/base/key.cpp
    src/base/endpoint_addr.cpp
    src/crypto/x25519.cpp
    src/crypto/hkdf.cpp
    src/crypto/chunk_hash.cpp
    src/crypto/merkle_tree.cpp
    src/crypto/signed_message.cpp
    src/protocol/replay_protection.cpp
    src/tls/crypto_provider.cpp
    src/tls/ed25519_core.cpp
    src/tls/ed25519_verifier.cpp
    src/tls/handshake_token_key.cpp
    src/tls/replay_window.cpp
    src/tls/address_token_store.cpp
    src/util/crypto.cpp
    src/util/rate_limiter.cpp
    src/util/atomic_write.cpp
    src/util/crc32.cpp
    src/util/file_permission.cpp
    src/util/key_file.cpp
    src/collection/model_manifest.cpp
    src/collection/parallel_downloader.cpp
    src/collection/shard_state_store.cpp
    src/endpoint/peer_error_tracker.cpp
    src/endpoint/connection_monitor.cpp
    third_party/openssl/src/evp_stub.cpp
)
BASE_OBJS=()
for f in "${BASE_SRCS[@]}"; do
    base=$(basename "$f" .cpp)
    objname="base_${base}"
    compile_one "$f" "$objname"
    BASE_OBJS+=("$objname")
done
link_lib "liblinoh-base.a" "${BASE_OBJS[@]}"
log ""

# ============================================================================
# Crate 2: linoh  (endpoint + net + protocol + linoh_c)
# ============================================================================
log "============================================================"
log "  Building liblinoh.a  Crate 2: endpoint + net + protocol + linoh_c"
log "============================================================"

CORE_SRCS=(
    src/endpoint/builder.cpp
    src/endpoint/connection.cpp
    src/endpoint/connection_state.cpp
    src/endpoint/stream_manager.cpp
    src/endpoint/packet_builder.cpp
    src/endpoint/endpoint.cpp
    src/endpoint/connection_migration.cpp
    src/endpoint/session_cache.cpp
    src/net/socket.cpp
    src/net/udp_transport.cpp
    src/net/udp_probe.cpp
    src/net/stun.cpp
    src/net/net_report.cpp
    src/net/happy_eyeballs.cpp
    src/net/holepuncher.cpp
    src/net/custom_transport.cpp
    src/net/cuda_buffer.cpp
    src/net/hw_accel.cpp
    src/net/route_monitor.cpp
    src/net/transport_selector.cpp
    src/protocol/packet.cpp
    src/protocol/router.cpp
    src/protocol/ack.cpp
    src/protocol/loss_recovery.cpp
    src/protocol/bbr_v2.cpp
    src/protocol/flow_control.cpp
    src/protocol/path_migration.cpp
    src/protocol/path_strategy.cpp
    src/protocol/application_message.cpp
    src/protocol/return_address.cpp
    src/protocol/session_id.cpp
    src/protocol/session_deduper.cpp
    src/protocol/compression.cpp
    src/protocol/addr_info.cpp
    src/protocol/connect_policy.cpp
    src/protocol/shard_bitfield.cpp
    src/protocol/ed25519_auth.cpp
    src/protocol/traffic_priority.cpp
    src/protocol/progress_report.cpp
    src/direct_return_manager.cpp
    src/protocol/multipath_selector.cpp
    src/protocol/multipath_coordinated_selector.cpp
    src/address_lookup/pkarr_publisher.cpp
    src/multimodal/buffer_pool.cpp
    src/multimodal/channel.cpp
    src/multimodal/channel_stats.cpp
    src/multimodal/collective.cpp
    src/multimodal/comm_planner.cpp
    src/multimodal/comm_planner_v2.cpp
    src/multimodal/control_channel.cpp
    src/multimodal/ep_channel.cpp
    src/multimodal/ep_frames.cpp
    src/multimodal/ep_session.cpp
    src/multimodal/expert_balancer.cpp
    src/multimodal/pe_engine.cpp
    src/multimodal/rh_engine.cpp
    src/multimodal/ring_engine.cpp
    src/multimodal/static_shape.cpp
    src/multimodal/sync_primitives.cpp
    src/multimodal/tensor_stream.cpp
    src/multimodal/tensor_pipeline.cpp
    src/multimodal/concurrent_forwarder.cpp
    src/multimodal/bf16.cpp
    src/multimodal/tree_engine.cpp
    src/multimodal/zero_copy.cpp
    src/fec/fec.cpp
    src/fec/fec_group.cpp
    src/observability/payload_audit.cpp
    src/tls/crypto_level.cpp
    src/net/mtu.cpp
    src/nat/ice_candidate.cpp
    src/nat/ice_session.cpp
    src/nat/cgn_detector.cpp
    src/nat/dual_stack.cpp
    src/nat/relay_pool.cpp
    src/nat/port_predictor.cpp
    src/nat/passive_endpoint_updater.cpp
    src/nat/nat_stats.cpp
    src/node_profile.cpp
    src/control_plane.cpp
    src/event_bus.cpp
    src/config_entry.cpp
    src/config_distributor.cpp
    src/event/event_loop.cpp
    src/event/shutdown_event.cpp
    src/event/timer_event.cpp
    src/event/linoh_event_source.cpp
    src/linoh_c.cpp
)
CORE_OBJS=()
for f in "${CORE_SRCS[@]}"; do
    base=$(basename "$f" .cpp)
    objname="core_${base}"
    compile_one "$f" "$objname"
    CORE_OBJS+=("$objname")
done
link_lib "liblinoh.a" "${CORE_OBJS[@]}"
log ""

# ============================================================================
# Crate 3: linoh-relay  (relay client/server/tls_channel/access_control)
# ============================================================================
log "============================================================"
log "  Building liblinoh-relay.a  Crate 3: relay client/server/tls_channel/access_control"
log "============================================================"

RELAY_SRCS=(
    src/relay/client.cpp
    src/relay/server.cpp
    src/relay/tls_channel.cpp
    src/relay/access_control.cpp
)
RELAY_OBJS=()
for f in "${RELAY_SRCS[@]}"; do
    base=$(basename "$f" .cpp)
    objname="relay_${base}"
    compile_one "$f" "$objname"
    RELAY_OBJS+=("$objname")
done
link_lib "liblinoh-relay.a" "${RELAY_OBJS[@]}"
log ""

# ============================================================================
# Crate 4: linoh-dns-server  (pkarr DNS server)
# ============================================================================
log "============================================================"
log "  Building liblinoh-dns-server.a  Crate 4: pkarr DNS server"
log "============================================================"

DNS_SRCS=(
    src/address_lookup/pkarr_server.cpp
)
DNS_OBJS=()
for f in "${DNS_SRCS[@]}"; do
    base=$(basename "$f" .cpp)
    objname="dns_${base}"
    compile_one "$f" "$objname"
    DNS_OBJS+=("$objname")
done
link_lib "liblinoh-dns-server.a" "${DNS_OBJS[@]}"
log ""

# ============================================================================
# Examples (Linux-compatible subset)
# ============================================================================
log "============================================================"
log "  Building examples"
log "============================================================"

# linoh_relay_bridge: tool, links only base (Ed25519 + SHA-512)
log "  linoh_relay_bridge.cpp"
$CXX $CXXFLAGS -c tools/linoh_relay_bridge.cpp -o build/linoh_relay_bridge.o 2>build/err_linoh_relay_bridge.txt || {
    log "FAILED: tools/linoh_relay_bridge.cpp"; cat build/err_linoh_relay_bridge.txt; exit 1; }
$CXX $LDFLAGS -o build/linoh_relay_bridge build/linoh_relay_bridge.o build/liblinoh-base.a build/liblinoh_zstd.a $LIBS 2>build/err_link_linoh_relay_bridge.txt || {
    log "FAILED: link linoh_relay_bridge"; cat build/err_link_linoh_relay_bridge.txt; exit 1; }

# relay_server_main: independent, links only linoh-relay + linoh-base
log "  relay_server_main.cpp"
$CXX $CXXFLAGS -c examples/relay_server_main.cpp -o build/relay_server_main.o 2>build/err_relay_server_main.txt || {
    log "FAILED: examples/relay_server_main.cpp"; cat build/err_relay_server_main.txt; exit 1; }
$CXX $LDFLAGS -o build/linoh-relay-server build/relay_server_main.o build/liblinoh-relay.a build/liblinoh-base.a build/liblinoh_zstd.a $LIBS 2>build/err_link_linoh-relay-server.txt || {
    log "FAILED: link linoh-relay-server"; cat build/err_link_linoh-relay-server.txt; exit 1; }

# pkarr_dns_server_main: independent, links only linoh-dns-server + linoh-base
log "  pkarr_dns_server_main.cpp"
$CXX $CXXFLAGS -c examples/pkarr_dns_server_main.cpp -o build/pkarr_dns_server_main.o 2>build/err_pkarr_dns_server_main.txt || {
    log "FAILED: examples/pkarr_dns_server_main.cpp"; cat build/err_pkarr_dns_server_main.txt; exit 1; }
$CXX $LDFLAGS -o build/linoh-dns-server build/pkarr_dns_server_main.o build/liblinoh-dns-server.a build/liblinoh-base.a build/liblinoh_zstd.a $LIBS 2>build/err_link_linoh-dns-server.txt || {
    log "FAILED: link linoh-dns-server"; cat build/err_link_linoh-dns-server.txt; exit 1; }

# linoh_echo_node: Linux-compatible patchbay echo node (T-LP2-003)
# Links full lib stack (uses linoh C API for endpoint/connection/stream)
log "  linoh_echo_node.cpp"
$CXX $CXXFLAGS -c examples/linoh_echo_node.cpp -o build/linoh_echo_node.o 2>build/err_linoh_echo_node.txt || {
    log "FAILED: examples/linoh_echo_node.cpp"; cat build/err_linoh_echo_node.txt; exit 1; }
$CXX $LDFLAGS -o build/linoh_echo_node build/linoh_echo_node.o build/liblinoh.a build/liblinoh-base.a build/liblinoh_zstd.a $LIBS 2>build/err_link_linoh_echo_node.txt || {
    log "FAILED: link linoh_echo_node"; cat build/err_link_linoh_echo_node.txt; exit 1; }

# Note: linoh_api_server/client, linoh_echo_server/client, linoh_rpc_example
# are Windows-only (use winsock2.h/WSAStartup directly without #ifdef guards).
# They are intentionally excluded from Linux build.
log ""

# ============================================================================
# Tests (core regression suite, mirrors build_all.bat)
# ============================================================================
log "============================================================"
log "  Building tests"
log "============================================================"

# All test binaries link against the full lib stack
TEST_LIBS="build/liblinoh.a build/liblinoh-base.a build/liblinoh-relay.a build/liblinoh-dns-server.a build/liblinoh_zstd.a"

# Build a single test: build_test <src.cpp> <outname>
build_test() {
    local src="$1" out="$2"
    local objname="test_${out}_obj"
    log "  $src"
    # 6-3: test_e2e_stress_server 单独用系统 OpenSSL（third_party/openssl 是 stub 头，无 EVP_Digest* API）
    if [ "$out" = "test_e2e_stress_server" ]; then
        local SERVER_CXXFLAGS="-std=c++20 -O2 -pthread -Wall -Wextra -Wno-unused-parameter -DLINOH_USE_STUB_ASIO -I. -Iinclude -Ithird_party/asio/include"
        if ! $CXX $SERVER_CXXFLAGS -c "$src" -o "build/${objname}.o" 2>build/err_${out}.txt; then
            log "FAILED: compile $src"
            cat "build/err_${out}.txt"
            exit 1
        fi
        if ! $CXX $LDFLAGS -o "build/${out}" "build/${objname}.o" $TEST_LIBS $LIBS -lcrypto 2>>build/err_${out}.txt; then
            log "FAILED: link $out"
            cat "build/err_${out}.txt"
            exit 1
        fi
        return
    fi
    if ! $CXX $CXXFLAGS -c "$src" -o "build/${objname}.o" 2>build/err_${out}.txt; then
        log "FAILED: compile $src"
        cat "build/err_${out}.txt"
        exit 1
    fi
    if ! $CXX $LDFLAGS -o "build/${out}" "build/${objname}.o" $TEST_LIBS $LIBS 2>>build/err_${out}.txt; then
        log "FAILED: link $out"
        cat "build/err_${out}.txt"
        exit 1
    fi
}

# Windows-only tests (skipped on Linux, use raw winsock without #ifdef)
WINDOWS_ONLY_TESTS=(
    "tests/test_relay_server.cpp:test_relay_server"
)

is_windows_only() {
    local src="$1"
    for pair in "${WINDOWS_ONLY_TESTS[@]}"; do
        local wsrc="${pair%:*}"
        if [ "$src" = "$wsrc" ]; then return 0; fi
    done
    return 1
}

# Test list (mirrors build_all.bat order; 56 of 57 tests, 1 Windows-only skipped)
# Format: "src_path:out_name"
TESTS=(
    "test_1rtt_diag.cpp:test_1rtt_diag"  # test_1rtt_diag lives in repo root
    "tests/test_zerortt.cpp:test_zerortt"
    "tests/test_phase4_integration.cpp:test_phase4"
    "tests/test_state_machine.cpp:test_state_machine"
    "tests/test_relay_server.cpp:test_relay_server"
    "tests/test_x25519_hkdf.cpp:test_x25519_hkdf"
    "tests/test_key_schedule.cpp:test_key_schedule"
    "tests/test_handshake_msg.cpp:test_handshake_msg"
    "tests/test_tls13_handshake.cpp:test_tls13_handshake"
    "tests/test_connection_tls13.cpp:test_connection_tls13"
    "tests/test_application_message.cpp:test_application_message"
    "tests/test_return_address.cpp:test_return_address"
    "tests/test_direct_return_manager.cpp:test_direct_return_manager"
    "tests/test_packet_number.cpp:test_packet_number"
    "tests/test_stream_close_frame.cpp:test_stream_close_frame"
    "tests/test_pto_early_retransmit.cpp:test_pto_early_retransmit"
    "tests/test_replay_window.cpp:test_replay_window"
    "tests/test_secure_buffer.cpp:test_secure_buffer"
    "tests/test_constant_time.cpp:test_constant_time"
    "tests/test_aead_nonce.cpp:test_aead_nonce"
    "tests/test_on_close_dedup.cpp:test_on_close_dedup"
    "tests/test_heartbeat.cpp:test_heartbeat"
    "tests/test_rpc_pool.cpp:test_rpc_pool"
    "tests/test_session_ticket.cpp:test_session_ticket"
    "tests/test_async_api.cpp:test_async_api"
    "tests/test_compressed_msg.cpp:test_compressed_msg"
    "tests/test_key_update.cpp:test_key_update"
    "tests/test_four_tuple.cpp:test_four_tuple"
    "tests/test_address_token_store.cpp:test_address_token_store"
    "tests/test_close_immediate.cpp:test_close_immediate"
    "tests/test_path_abandon.cpp:test_path_abandon"
    "tests/test_stun.cpp:test_stun"
    "tests/test_net_report.cpp:test_net_report"
    "tests/test_happy_eyeballs.cpp:test_happy_eyeballs"
    "tests/test_path_strategy.cpp:test_path_strategy"
    "tests/test_access_control.cpp:test_access_control"
    "tests/test_rate_limiter.cpp:test_rate_limiter"
    "tests/test_holepuncher.cpp:test_holepuncher"
    "tests/test_custom_transport.cpp:test_custom_transport"
    "tests/test_dns_fallback.cpp:test_dns_fallback"
    "tests/test_multimodal_channel.cpp:test_multimodal_channel"
    "tests/test_control_channel.cpp:test_control_channel"
    "tests/test_tensor_stream.cpp:test_tensor_stream"
    "tests/test_tensor_stream_c_api.cpp:test_tensor_stream_c_api"  # v5.1.0 T-LA
    "tests/test_fec.cpp:test_fec"
    "tests/test_crypto_level.cpp:test_crypto_level"
    "tests/test_multipath_selector.cpp:test_multipath_selector"
    "tests/test_mtu.cpp:test_mtu"
    "tests/test_sync.cpp:test_sync"
    "tests/test_stat_trackers.cpp:test_stat_trackers"
    "tests/test_task_pool.cpp:test_task_pool"
    "tests/test_ports.cpp:test_ports"
    "tests/test_ice_candidate.cpp:test_ice_candidate"
    "tests/test_ice_session.cpp:test_ice_session"
    "tests/test_cgn_detector.cpp:test_cgn_detector"
    "tests/test_dual_stack.cpp:test_dual_stack"
    "tests/test_relay_pool.cpp:test_relay_pool"
    # v1.5 P2-1+P2-3 loss_recovery
    "tests/test_loss_recovery_p2.cpp:test_loss_recovery_p2"
    # v1.5.0.2.6 loss_recovery instrumentation
    "tests/test_loss_recovery_instrumentation.cpp:test_loss_recovery_instrumentation"
    # v1.5.0.1 hotfix tests (4)
    "tests/test_retransmit_oos_recovery.cpp:test_retransmit_oos_recovery"
    "tests/test_payload_audit.cpp:test_payload_audit"
    "tests/test_periodic_fc_emission.cpp:test_periodic_fc_emission"
    "tests/test_iw10.cpp:test_iw10"
    # v3.1.4 hotfix test (A9 Stream FIN-only half-close)
    "tests/test_stream_fin_half_close.cpp:test_stream_fin_half_close"
    # v1.5.0.1 E2E stress test (server only, client is Windows MSVC C)
    "tests/test_e2e_stress_server.cpp:test_e2e_stress_server"
)

SKIPPED=0
BUILT=0
for entry in "${TESTS[@]}"; do
    src="${entry%%:*}"
    out="${entry#*:}"

    # Handle Windows-only skip
    if is_windows_only "$src"; then
        log "  SKIP $src (Windows-only: uses raw winsock without #ifdef)"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    build_test "$src" "$out"
    BUILT=$((BUILT + 1))
done

log ""
log "============================================================"
log "  Build Summary"
log "============================================================"
log "Compiler:  $CXX"
log "Flags:     $CXXFLAGS"
log ""
log "Libraries (build/):"
ls -1 build/lib*.a 2>/dev/null || log "  (none)"
log ""
log "Executables (build/):"
ls -1 build/linoh-relay-server build/linoh-dns-server build/linoh_relay_bridge 2>/dev/null || log "  (none)"
log ""
log "Tests built:     $BUILT"
log "Tests skipped:   $SKIPPED (Windows-only)"
log ""
log "Build completed successfully."
