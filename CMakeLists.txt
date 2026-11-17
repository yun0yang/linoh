cmake_minimum_required(VERSION 3.20)
project(linoh
    VERSION 2.0.0
    DESCRIPTION "linoh — light-weight iroh: P2P QUIC networking in modern C++"
    LANGUAGES C CXX)  # T-015(L6): C 必须启用，否则 zstd vendored .c 被静默忽略（空库）；ASM 仅 Linux（见下方条件）

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Platform-specific compile flags
# ---------------------------------------------------------------------------
if(ANDROID)
    # Android NDK 交叉编译配置
    # - 使用 gnu++20 而非 c++20 以支持 POSIX 扩展（pthread_* 等）
    # - 开启 16KiB page size 支持（Android 15+ 新设备必需）
    # - 定义 LINOH_PLATFORM_ANDROID 标识宏
    set(CMAKE_CXX_EXTENSIONS ON)  # 启用 GNU 扩展
    add_compile_options(-std=gnu++20)
    add_compile_definitions(LINOH_PLATFORM_ANDROID=1)
    # 16KiB page size 支持（NDK r27+ 配合 ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON）
    add_link_options(-Wl,-z,max-page-size=16384)
    # Android log 库（__android_log_print）
    find_library(LOG_LIB log REQUIRED)
    message(STATUS "Android NDK 交叉编译模式")
    message(STATUS "  ABI:               ${ANDROID_ABI}")
    message(STATUS "  minSdkVersion:     ${ANDROID_PLATFORM}")
    message(STATUS "  C++ 标准:          gnu++20 (with POSIX extensions)")
    message(STATUS "  16KiB page size:   已启用")
elseif(MSVC)
    add_compile_options(/W4 /permissive- /EHsc /bigobj /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-pedantic)
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(LINOH_BUILD_EXAMPLES    "Build examples (Windows-only demos)" OFF)
option(LINOH_BUILD_TESTS       "Build core regression tests" OFF)
option(LINOH_BUILD_SERVERS     "Build server binaries (relay, pkarr)" ON)
option(LINOH_BUILD_TOOLS       "Build standalone tools (linoh_relay_bridge)" ON)
option(LINOH_ENABLE_TSAN       "Enable ThreadSanitizer for data-race detection (Clang/GCC recommended; MSVC experimental)" OFF)

# ---------------------------------------------------------------------------
# Common include paths + compile definitions (mirror build_all.bat / .sh)
# ---------------------------------------------------------------------------
add_library(linoh_common_iface INTERFACE)
target_include_directories(linoh_common_iface INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/asio/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl/include)
target_compile_definitions(linoh_common_iface INTERFACE LINOH_USE_STUB_ASIO=1)

find_package(Threads REQUIRED)

# Android 平台额外链接 log 库（供后续 JNI 层使用 __android_log_print）
if(ANDROID)
    target_link_libraries(linoh_common_iface INTERFACE ${LOG_LIB})
endif()

# ---------------------------------------------------------------------------
# Crate 1: linoh-base  (base + crypto + tls + util)
# ---------------------------------------------------------------------------
add_library(linoh-base STATIC
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
    third_party/openssl/src/evp_stub.cpp)
target_link_libraries(linoh-base PUBLIC linoh_common_iface Threads::Threads)

# ---------------------------------------------------------------------------
# Crate zstd: vendored zstd 1.5.6 compression (C sources, V3.4)
# ---------------------------------------------------------------------------
add_library(linoh_zstd STATIC
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
    third_party/zstd/dictBuilder/zdict.c)
target_include_directories(linoh_zstd PUBLIC third_party/zstd third_party/zstd/common)  # common/xxhash.h（O1.3 dict info 校验）
target_compile_definitions(linoh_zstd PRIVATE ZSTD_STATIC_LINKING_ONLY ZSTD_LEGACY_SUPPORT=0)
# T-015(L6): x86_64 汇编加速循环（缺它 Linux 链接报 HUF_*_asm_loop undefined）
# MSVC 不需要（纯 C 回退路径），且 MSVC_RUNTIME_LIBRARY 与 ASM 语言冲突
if(NOT MSVC)
    enable_language(ASM)
    target_sources(linoh_zstd PRIVATE third_party/zstd/decompress/huf_decompress_amd64.S)
endif()

if(MSVC)
    target_compile_options(linoh_zstd PRIVATE /TC /utf-8)
endif()
set_target_properties(linoh_zstd PROPERTIES LINKER_LANGUAGE CXX)

# ---------------------------------------------------------------------------
# Crate 2: linoh  (endpoint + net + protocol + linoh_c + multimodal + fec + nat)
# ---------------------------------------------------------------------------
add_library(linoh STATIC
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
    # v4.3.0 M7: select! 事件驱动（EventLoop + 4 个内置 EventSource）
    src/event/event_loop.cpp
    src/event/shutdown_event.cpp
    src/event/timer_event.cpp
    src/event/linoh_event_source.cpp
    src/linoh_c.cpp)
target_link_libraries(linoh PUBLIC linoh-base linoh_zstd)

# ---------------------------------------------------------------------------
# Crate 3: linoh-relay  (relay client/server/tls_channel/access_control)
# ---------------------------------------------------------------------------
add_library(linoh-relay STATIC
    src/relay/client.cpp
    src/relay/server.cpp
    src/relay/tls_channel.cpp
    src/relay/access_control.cpp)
target_link_libraries(linoh-relay PUBLIC linoh-base)

# ---------------------------------------------------------------------------
# Crate 4: linoh-dns-server  (pkarr DNS server)
# ---------------------------------------------------------------------------
add_library(linoh-dns-server STATIC
    src/address_lookup/pkarr_server.cpp)
target_link_libraries(linoh-dns-server PUBLIC linoh-base)

# ---------------------------------------------------------------------------
# Servers — standalone deployable services
# ---------------------------------------------------------------------------
if(LINOH_BUILD_SERVERS)
    add_executable(linoh-relay-server examples/relay_server_main.cpp)
    target_link_libraries(linoh-relay-server PRIVATE linoh-relay linoh-base)

    add_executable(linoh-dns-server-exe examples/pkarr_dns_server_main.cpp)
    target_link_libraries(linoh-dns-server-exe PRIVATE linoh-dns-server linoh-base)

    message(STATUS "linoh servers: linoh-relay-server, linoh-dns-server-exe")
endif()

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
if(LINOH_BUILD_TOOLS)
    add_executable(linoh_relay_bridge tools/linoh_relay_bridge.cpp)
    target_link_libraries(linoh_relay_bridge PRIVATE linoh-base)

    message(STATUS "linoh tools:   linoh_relay_bridge")
endif()

# ---------------------------------------------------------------------------
# Examples (Windows-only demos; Linux uses build_all.sh which skips them)
# ---------------------------------------------------------------------------
if(LINOH_BUILD_EXAMPLES)
    if(WIN32)
        add_executable(linoh_echo_server examples/linoh_echo_server.cpp)
        target_link_libraries(linoh_echo_server PRIVATE linoh)

        add_executable(linoh_api_server examples/linoh_api_server.cpp)
        target_link_libraries(linoh_api_server PRIVATE linoh)

        message(STATUS "linoh examples (Windows-only): linoh_echo_server, linoh_api_server")
    else()
        message(STATUS "linoh examples are Windows-only; skipped on non-Windows")
    endif()
endif()

# ---------------------------------------------------------------------------
# Tests — core regression suite (mirrors build_all.bat / build_all.sh list)
# ---------------------------------------------------------------------------
if(LINOH_BUILD_TESTS)
    enable_testing()

    # Helper function: register a single test executable
    # linoh_add_test(<name> <src>)
    function(linoh_add_test name src)
        add_executable(${name} ${src})
        target_link_libraries(${name} PRIVATE linoh linoh-base linoh-relay linoh-dns-server)
        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    # Core regression tests (54 of 55; test_relay_server is Windows-only and skipped)
    linoh_add_test(test_1rtt_diag        test_1rtt_diag.cpp)
    linoh_add_test(test_zerortt          tests/test_zerortt.cpp)
    linoh_add_test(test_phase4           tests/test_phase4_integration.cpp)
    linoh_add_test(test_state_machine    tests/test_state_machine.cpp)
    if(WIN32)
        linoh_add_test(test_relay_server tests/test_relay_server.cpp)
    endif()
    linoh_add_test(test_x25519_hkdf      tests/test_x25519_hkdf.cpp)
    linoh_add_test(test_key_schedule     tests/test_key_schedule.cpp)
    linoh_add_test(test_handshake_msg    tests/test_handshake_msg.cpp)
    linoh_add_test(test_tls13_handshake  tests/test_tls13_handshake.cpp)
    linoh_add_test(test_connection_tls13 tests/test_connection_tls13.cpp)
    # v5.1.0: PSK_IDENTITY 帧（K-LINOH-PEERMISMATCH 根治）
    linoh_add_test(test_psk_peer_identity tests/test_psk_peer_identity.cpp)
    linoh_add_test(test_application_message tests/test_application_message.cpp)
    linoh_add_test(test_return_address   tests/test_return_address.cpp)
    linoh_add_test(test_direct_return_manager tests/test_direct_return_manager.cpp)
    linoh_add_test(test_direct_return_e2e tests/test_direct_return_e2e.cpp)
    linoh_add_test(test_congestion_auto_switch tests/test_congestion_auto_switch.cpp)
    linoh_add_test(test_zero_copy_pipeline  tests/test_zero_copy_pipeline.cpp)
    linoh_add_test(test_fec_simd            tests/test_fec_simd.cpp)
    linoh_add_test(test_fec_adaptive tests/test_fec_adaptive.cpp)  # O3: FEC 自适应控制器
    linoh_add_test(test_connection_stability tests/test_connection_stability.cpp)
    linoh_add_test(test_event_bus        tests/test_event_bus.cpp)
    linoh_add_test(test_session_id       tests/test_session_id.cpp)
    linoh_add_test(test_session_deduper  tests/test_session_deduper.cpp)
    linoh_add_test(test_compression      tests/test_compression.cpp)
    linoh_add_test(test_message_session_id tests/test_message_session_id.cpp)
    linoh_add_test(test_message_compression tests/test_message_compression.cpp)
    linoh_add_test(test_protocol_dict_compression tests/test_protocol_dict_compression.cpp)  # O1: 协议字典压缩
    linoh_add_test(test_tlv tests/test_tlv.cpp)  # W1.2: TLV 编解码基础设施
    linoh_add_test(test_multipath_role_hash tests/test_multipath_role_hash.cpp)  # W2.2: FEC 冗余块路径分集
    linoh_add_test(test_holepunch_quiesce tests/test_holepunch_quiesce.cpp)  # S6: 打洞静默收敛
    linoh_add_test(test_socket_strip tests/test_socket_strip.cpp)  # S2: Socket 层分集 API
    linoh_add_test(test_holepunch_cache tests/test_holepunch_cache.cpp)  # S6-3: 打洞结果缓存
    linoh_add_test(test_capabilities     tests/test_capabilities.cpp)
    linoh_add_test(test_capi_session_compress tests/test_capi_session_compress.cpp)
    linoh_add_test(test_event_bus_cross_domain tests/test_event_bus_cross_domain.cpp)
    linoh_add_test(test_packet_number    tests/test_packet_number.cpp)
    linoh_add_test(test_stream_close_frame tests/test_stream_close_frame.cpp)
    linoh_add_test(test_stream_fin_half_close tests/test_stream_fin_half_close.cpp)
    linoh_add_test(test_pto_early_retransmit tests/test_pto_early_retransmit.cpp)
    linoh_add_test(test_replay_window    tests/test_replay_window.cpp)
    linoh_add_test(test_secure_buffer    tests/test_secure_buffer.cpp)
    linoh_add_test(test_constant_time    tests/test_constant_time.cpp)
    linoh_add_test(test_aead_nonce       tests/test_aead_nonce.cpp)
    linoh_add_test(test_on_close_dedup   tests/test_on_close_dedup.cpp)
    linoh_add_test(test_heartbeat        tests/test_heartbeat.cpp)
    linoh_add_test(test_rpc_pool         tests/test_rpc_pool.cpp)
    linoh_add_test(test_session_ticket   tests/test_session_ticket.cpp)
    linoh_add_test(test_async_api        tests/test_async_api.cpp)
    linoh_add_test(test_compressed_msg   tests/test_compressed_msg.cpp)
    linoh_add_test(test_key_update       tests/test_key_update.cpp)
    linoh_add_test(test_four_tuple       tests/test_four_tuple.cpp)
    linoh_add_test(test_address_token_store tests/test_address_token_store.cpp)
    linoh_add_test(test_close_immediate  tests/test_close_immediate.cpp)
    linoh_add_test(test_path_abandon     tests/test_path_abandon.cpp)
    linoh_add_test(test_stun             tests/test_stun.cpp)
    linoh_add_test(test_net_report       tests/test_net_report.cpp)
    linoh_add_test(test_happy_eyeballs   tests/test_happy_eyeballs.cpp)
    linoh_add_test(test_path_strategy    tests/test_path_strategy.cpp)
    linoh_add_test(test_access_control   tests/test_access_control.cpp)
    linoh_add_test(test_rate_limiter     tests/test_rate_limiter.cpp)
    linoh_add_test(test_holepuncher      tests/test_holepuncher.cpp)
    linoh_add_test(test_custom_transport tests/test_custom_transport.cpp)
    linoh_add_test(test_dns_fallback     tests/test_dns_fallback.cpp)
    linoh_add_test(test_multimodal_channel tests/test_multimodal_channel.cpp)
    linoh_add_test(test_control_channel  tests/test_control_channel.cpp)
    linoh_add_test(test_tensor_stream    tests/test_tensor_stream.cpp)
    linoh_add_test(test_tensor_stream_c_api tests/test_tensor_stream_c_api.cpp)  # v5.1.0 T-LA
    linoh_add_test(test_fec              tests/test_fec.cpp)
    linoh_add_test(test_crypto_level     tests/test_crypto_level.cpp)
    linoh_add_test(test_multipath_selector tests/test_multipath_selector.cpp)
    linoh_add_test(test_mtu              tests/test_mtu.cpp)
    linoh_add_test(test_sync             tests/test_sync.cpp)
    linoh_add_test(test_stat_trackers    tests/test_stat_trackers.cpp)
    linoh_add_test(test_task_pool        tests/test_task_pool.cpp)
    linoh_add_test(test_ports            tests/test_ports.cpp)
    linoh_add_test(test_ice_candidate    tests/test_ice_candidate.cpp)
    linoh_add_test(test_ice_session      tests/test_ice_session.cpp)
    linoh_add_test(test_cgn_detector     tests/test_cgn_detector.cpp)
    linoh_add_test(test_dual_stack       tests/test_dual_stack.cpp)
    linoh_add_test(test_relay_pool       tests/test_relay_pool.cpp)
    linoh_add_test(test_port_predictor   tests/test_port_predictor.cpp)
    linoh_add_test(test_nat_stats        tests/test_nat_stats.cpp)
    linoh_add_test(test_nat_prediction_model tests/test_nat_prediction_model.cpp)
    linoh_add_test(test_endpoint_nat_hardening tests/test_endpoint_nat_hardening.cpp)
    linoh_add_test(test_cgn_dynamic_threshold tests/test_cgn_dynamic_threshold.cpp)
    linoh_add_test(test_holepuncher_adaptive tests/test_holepuncher_adaptive.cpp)
    linoh_add_test(test_endpoint_last_attempt tests/test_endpoint_last_attempt.cpp)

    # P9.1: LossDetector + RttEstimator 线程安全验证
    #   3 线程并发（recv/send/timeout）+ 计数器守恒 + RttEstimator 跨线程读写
    #   默认 3s 快速回归；TSan 验收传 30（30s 3 线程 0 data race）
    linoh_add_test(test_loss_recovery_thread_safety tests/test_loss_recovery_thread_safety.cpp)

    # P9.1: ThreadSanitizer 配置 — LINOH_ENABLE_TSAN=ON 时全量加锁验证
    #   MSVC TSan 仍为实验性（/fsanitize=thread），生产验收建议 Clang/Linux
    if(LINOH_ENABLE_TSAN)
        if(MSVC)
            message(WARNING "LINOH_ENABLE_TSAN: MSVC ThreadSanitizer is experimental (VS 17.14). "
                            "For reliable TSan use Clang (clang-cl / -fsanitize=thread). "
                            "Attempting /fsanitize=thread ...")
            target_compile_options(linoh_common_iface INTERFACE
                $<$<COMPILE_LANGUAGE:CXX>:/fsanitize=thread>)
        else()
            target_compile_options(linoh_common_iface INTERFACE -fsanitize=thread -g)
            target_link_options(linoh_common_iface INTERFACE -fsanitize=thread)
        endif()
        # TSan 首个 race 即终止，便于定位
        set_tests_properties(test_loss_recovery_thread_safety PROPERTIES
            ENVIRONMENT "TSAN_OPTIONS=halt_on_error=1 second_deadlock_stack=1")
        message(STATUS "  ThreadSanitizer enabled — "
                       "run: ctest -R test_loss_recovery_thread_safety --output-on-failure")
    endif()

    # v3.7.0 可靠性强化：sha256 chunk 校验 + Merkle Root + 原子文件操作
    linoh_add_test(test_chunk_hash    tests/test_chunk_hash.cpp)
    linoh_add_test(test_atomic_write  tests/test_atomic_write.cpp)

    # v4.5.0 endpoint_id 密钥文件持久化统一（42B 容器 + 旧格式兼容 + 原子写 + 权限）
    linoh_add_test(test_key_file_persistence tests/test_key_file_persistence.cpp)

    # v3.7.1/v3.7.2 可靠性强化：内容寻址 manifest + 原子性
    linoh_add_test(test_model_manifest tests/test_model_manifest.cpp)

    # v3.7.3 可靠性强化：并行下载器（线程池 + 重试 + 并发）
    linoh_add_test(test_parallel_downloader tests/test_parallel_downloader.cpp)

    # v3.7.4 可靠性强化：断点续传状态存储
    linoh_add_test(test_shard_state_store  tests/test_shard_state_store.cpp)

    # v3.8.0 安全与故障自动化：per-peer 错误计数自动降级
    linoh_add_test(test_peer_error_tracker tests/test_peer_error_tracker.cpp)

    # v3.8.4 安全与故障自动化：TensorStream Merkle Root 完整性校验
    linoh_add_test(test_merkle_tree     tests/test_merkle_tree.cpp)

    # v3.8.2 安全与故障自动化：控制面 Ed25519 签名信封
    linoh_add_test(test_signed_message  tests/test_signed_message.cpp)

    # v3.8.3 安全与故障自动化：控制面 nonce + timestamp 防重放
    linoh_add_test(test_replay_protection tests/test_replay_protection.cpp)

    # v3.9.5 M5: 角色 ALPN 子集（NodeRole + role_default_alpns + is_role_authorized）
    linoh_add_test(test_role_alpn tests/test_role_alpn.cpp)

    # v3.9.6 M17: 逐 chunk sha256 增量校验（ShardHashAnnounce + chunk verify）
    linoh_add_test(test_chunk_verify_stream tests/test_chunk_verify_stream.cpp)

    # v4.0.0 M18: 地址交换协议分级（AddrInfoLevel + DirectAddress + AddrInfoPayload）
    linoh_add_test(test_addr_info tests/test_addr_info.cpp)

    # v4.0.1 M19: 连接策略直连优先（ConnectPolicy + ConnectDecision + CGN 联动）
    linoh_add_test(test_connect_policy tests/test_connect_policy.cpp)

    # v4.0.2 M20: 分片可用性同步（ShardBitfield + RLE 压缩 + Observe 帧）
    linoh_add_test(test_shard_bitfield tests/test_shard_bitfield.cpp)

    # v4.0.3 M15: 跨集群 Ed25519 挑战认证（AuthChallenge + AuthResponse + AuthManager）
    linoh_add_test(test_ed25519_auth tests/test_ed25519_auth.cpp)

    # v4.0.4 M22: 连接迁移协调器（MigrationConfig + 状态机 + PATH_CHALLENGE/RESPONSE 协调）
    linoh_add_test(test_connection_migration tests/test_connection_migration.cpp)

    # v4.0.5 M23: 流量优先级 QoS（TrafficPriority + PriorityConfig + WeightedFairQueue WFQ）
    linoh_add_test(test_traffic_priority tests/test_traffic_priority.cpp)

    # v4.3.0 M7: select! 事件循环（EventLoop + EventSource + C-API + 48 单元测试）
    linoh_add_test(test_event_loop tests/test_event_loop.cpp)

    # v4.3.0 M16: 三键 peer 排序（BandwidthTier + BandwidthTierStrategy）
    linoh_add_test(test_bandwidth_tier_strategy tests/test_bandwidth_tier_strategy.cpp)

    # v4.3.0 M21: 双层进度上报（ProgressReport 帧 + MethodId 0x0065）
    linoh_add_test(test_progress_report tests/test_progress_report.cpp)

    # v3.9.0 高性能网络传输：QUIC 参数 + BBR v2 pacing 限速
    linoh_add_test(test_transport_config tests/test_transport_config.cpp)

    # v3.9.2 高性能网络传输：异步序列化流水线 TensorPipeline
    linoh_add_test(test_tensor_pipeline tests/test_tensor_pipeline.cpp)

    # v3.9.3 高性能网络传输：FuturesUnordered 并发转发 ConcurrentForwarder
    linoh_add_test(test_concurrent_forwarder tests/test_concurrent_forwarder.cpp)

    # v3.9.1 高性能网络传输：ConnectionMonitor 带宽反馈闭环
    linoh_add_test(test_connection_monitor tests/test_connection_monitor.cpp)

    # v3.9.4 高性能网络传输：bf16 hidden_state 透明传输
    linoh_add_test(test_bf16_transport tests/test_bf16_transport.cpp)

    message(STATUS "linoh tests:   78 core regression tests registered (test_relay_server Windows-only)")

    # -------------------------------------------------------------------------
    # v4.3.0 M21: 端到端集成测试（默认 OFF，CI 环境开启）
    # -------------------------------------------------------------------------
    option(LINOH_BUILD_E2E_TESTS "Build end-to-end integration tests" OFF)
    if(LINOH_BUILD_E2E_TESTS)
        # E2eHarness helper + 4 e2e 测试用例（覆盖多模态 + 事件循环 + 进度上报）
        function(linoh_add_e2e_test name src)
            add_executable(${name} ${src})
            target_link_libraries(${name} PRIVATE linoh linoh-base linoh-relay linoh-dns-server)
            target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
            add_test(NAME ${name} COMMAND ${name})
        endfunction()

        linoh_add_e2e_test(e2e_pp_chain    tests/e2e/e2e_pp_chain.cpp)
        linoh_add_e2e_test(e2e_multimodal  tests/e2e/e2e_multimodal.cpp)
        linoh_add_e2e_test(e2e_event_loop  tests/e2e/e2e_event_loop.cpp)
        linoh_add_e2e_test(e2e_progress    tests/e2e/e2e_progress.cpp)

        message(STATUS "linoh e2e tests: 4 end-to-end tests registered (pp_chain, multimodal, event_loop, progress)")
    endif()
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(TARGETS linoh-base linoh linoh-relay linoh-dns-server
    EXPORT linoh-targets
    ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

message(STATUS "")
message(STATUS "linoh ${PROJECT_VERSION} configured successfully")
message(STATUS "  C++ Standard:       C++20")
message(STATUS "  Build type:         ${CMAKE_BUILD_TYPE}")
message(STATUS "  Crates:             linoh-base, linoh, linoh-relay, linoh-dns-server")
if(ANDROID)
    message(STATUS "  Platform:           Android (${ANDROID_ABI}, ${ANDROID_PLATFORM})")
    message(STATUS "  16KiB page size:    enabled")
else()
    message(STATUS "  Platform:           ${CMAKE_HOST_SYSTEM_NAME}")
endif()
message(STATUS "  LINOH_BUILD_SERVERS: ${LINOH_BUILD_SERVERS}")
message(STATUS "  LINOH_BUILD_TOOLS:   ${LINOH_BUILD_TOOLS}")
message(STATUS "  LINOH_BUILD_TESTS:   ${LINOH_BUILD_TESTS}")
