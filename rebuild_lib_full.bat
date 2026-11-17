@echo off
REM ============================================================================
REM  linoh.lib full rebuild (v4.8.0 multimodal tunnel)
REM  全量重编 linoh.lib（含 linoh_c.cpp + path_strategy.cpp 等所有核心源文件）
REM  不编译测试和示例，仅生成 linoh.lib + linoh_zstd.lib + linoh-base.lib + linoh-relay.lib
REM ============================================================================
setlocal enabledelayedexpansion

set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

set "VCVARSALL="
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VSINSTALL=%%i"
    )
    if defined VSINSTALL (
        set "VCVARSALL=!VSINSTALL!\VC\Auxiliary\Build\vcvarsall.bat"
    )
)

if not exist "%VCVARSALL%" (
    for %%E in (Community Professional Enterprise BuildTools) do (
        if not exist "%VCVARSALL%" (
            if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat" (
                set "VCVARSALL=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat"
            )
        )
    )
)

if not exist "%VCVARSALL%" (
    echo ERROR: Could not find vcvarsall.bat.
    exit /b 1
)

echo Using MSVC: %VCVARSALL%
call "%VCVARSALL%" x64
if errorlevel 1 (
    echo ERROR: Failed to initialize MSVC environment.
    exit /b 1
)

cd /d %~dp0
if not exist build mkdir build

set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO /DLINOH_COMPILE_LOG_LEVEL=2 /D_WIN32_WINNT=0x0600 /DNTDDI_VERSION=0x06000000 /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include /Ithird_party\zstd /Ithird_party\zstd\common"

echo ============================================================================
echo  Building linoh_zstd.lib  Crate 1: zstd compression
echo ============================================================================

set "ZSTD_OBJS="
for %%F in (
  third_party\zstd\common\debug.c
  third_party\zstd\common\entropy_common.c
  third_party\zstd\common\error_private.c
  third_party\zstd\common\fse_decompress.c
  third_party\zstd\common\pool.c
  third_party\zstd\common\threading.c
  third_party\zstd\common\xxhash.c
  third_party\zstd\common\zstd_common.c
  third_party\zstd\compress\fse_compress.c
  third_party\zstd\compress\hist.c
  third_party\zstd\compress\huf_compress.c
  third_party\zstd\compress\zstd_compress.c
  third_party\zstd\compress\zstd_compress_literals.c
  third_party\zstd\compress\zstd_compress_sequences.c
  third_party\zstd\compress\zstd_compress_superblock.c
  third_party\zstd\compress\zstd_double_fast.c
  third_party\zstd\compress\zstd_fast.c
  third_party\zstd\compress\zstd_lazy.c
  third_party\zstd\compress\zstd_ldm.c
  third_party\zstd\compress\zstd_opt.c
  third_party\zstd\compress\zstdmt_compress.c
  third_party\zstd\decompress\huf_decompress.c
  third_party\zstd\decompress\zstd_ddict.c
  third_party\zstd\decompress\zstd_decompress.c
  third_party\zstd\decompress\zstd_decompress_block.c
  third_party\zstd\dictBuilder\cover.c
  third_party\zstd\dictBuilder\divsufsort.c
  third_party\zstd\dictBuilder\fastcover.c
  third_party\zstd\dictBuilder\zdict.c
) do (
  cl %CXXFLAGS% %%F /c /Fo:build\zstd_%%~nF.obj >nul 2>&1
  set "ZSTD_OBJS=!ZSTD_OBJS! build\zstd_%%~nF.obj"
)
lib /NOLOGO /OUT:"build\linoh_zstd.lib" %ZSTD_OBJS%
echo   linoh_zstd.lib done

echo ============================================================================
echo  Building linoh.lib  Crate 2: endpoint + net + protocol + linoh_c (FULL REBUILD)
echo ============================================================================

set "CORE_OBJS="
for %%F in (
  src\endpoint\builder.cpp
  src\endpoint\connection.cpp
  src\endpoint\connection_state.cpp
  src\endpoint\stream_manager.cpp
  src\endpoint\packet_builder.cpp
  src\endpoint\endpoint.cpp
  src\endpoint\connection_migration.cpp
  src\endpoint\session_cache.cpp
  src\net\socket.cpp
  src\net\udp_transport.cpp
  src\net\stun.cpp
  src\net\net_report.cpp
  src\net\happy_eyeballs.cpp
  src\net\holepuncher.cpp
  src\net\udp_probe.cpp
  src\net\custom_transport.cpp
  src\net\hw_accel.cpp
  src\net\transport_selector.cpp
  src\net\cuda_buffer.cpp
  src\net\route_monitor.cpp
  src\net\bidirectional_holepuncher.cpp
  src\protocol\packet.cpp
  src\protocol\router.cpp
  src\protocol\ack.cpp
  src\protocol\loss_recovery.cpp
  src\protocol\bbr_v2.cpp
  src\protocol\flow_control.cpp
  src\protocol\path_migration.cpp
  src\protocol\path_strategy.cpp
  src\protocol\application_message.cpp
  src\protocol\return_address.cpp
  src\protocol\session_id.cpp
  src\protocol\session_deduper.cpp
  src\protocol\compression.cpp
  src\protocol\capabilities.cpp
  src\protocol\addr_info.cpp
  src\protocol\connect_policy.cpp
  src\protocol\shard_bitfield.cpp
  src\protocol\ed25519_auth.cpp
  src\protocol\traffic_priority.cpp
  src\direct_return_manager.cpp
  src\address_lookup\pkarr_publisher.cpp
  src\multimodal\channel.cpp
  src\multimodal\channel_stats.cpp
  src\multimodal\control_channel.cpp
  src\multimodal\tensor_stream.cpp
  src\multimodal\tensor_pipeline.cpp
  src\multimodal\concurrent_forwarder.cpp
  src\multimodal\bf16.cpp
  src\multimodal\ep_frames.cpp
  src\multimodal\ep_channel.cpp
  src\multimodal\sync_primitives.cpp
  src\multimodal\collective.cpp
  src\multimodal\buffer_pool.cpp
  src\multimodal\static_shape.cpp
  src\multimodal\zero_copy.cpp
  src\multimodal\comm_planner.cpp
  src\multimodal\comm_planner_v2.cpp
  src\multimodal\ring_engine.cpp
  src\multimodal\tree_engine.cpp
  src\multimodal\rh_engine.cpp
  src\multimodal\pe_engine.cpp
  src\multimodal\expert_balancer.cpp
  src\multimodal\ep_session.cpp
  src\fec\fec.cpp
  src\fec\fec_group.cpp
  src\fec\fec_adaptive.cpp
  src\tls\crypto_level.cpp
  src\protocol\multipath_selector.cpp
  src\protocol\multipath_coordinated_selector.cpp
  src\net\mtu.cpp
  src\nat\ice_candidate.cpp
  src\nat\holepunch_cache.cpp
  src\nat\ice_session.cpp
  src\nat\cgn_detector.cpp
  src\nat\dual_stack.cpp
  src\nat\relay_pool.cpp
  src\nat\port_predictor.cpp
  src\nat\nat_stats.cpp
  src\nat\passive_endpoint_updater.cpp
  src\nat\server_config.cpp
  src\net\network_rebuilder.cpp
  src\node_profile.cpp
  src\control_plane.cpp
  src\event_bus.cpp
  src\config_entry.cpp
  src\config_distributor.cpp
  src\protocol\progress_report.cpp
  src\event\event_loop.cpp
  src\event\shutdown_event.cpp
  src\event\timer_event.cpp
  src\event\linoh_event_source.cpp
  src\linoh_c.cpp
  src\observability\payload_audit.cpp
) do (
  echo   compile %%F
  cl %CXXFLAGS% %%F /c /Fo:build\core_%%~nF.obj >build\err_core_%%~nF.txt 2>&1
  if errorlevel 1 (
    echo FAILED: %%F
    type build\err_core_%%~nF.txt
    exit /b 1
  )
  set "CORE_OBJS=!CORE_OBJS! build\core_%%~nF.obj"
)

echo   link linoh.lib
lib /NOLOGO /OUT:"build\linoh.lib" %CORE_OBJS% %ZSTD_OBJS%
echo.

echo ============================================================================
echo  Building linoh-base.lib  Crate 3: base crypto + util + address_lookup
echo ============================================================================

set "BASE_OBJS="
for %%F in (
  src\base\key.cpp
  src\base\endpoint_addr.cpp
  src\util\crypto.cpp
  src\util\crc32.cpp
  src\util\atomic_write.cpp
  src\util\file_permission.cpp
  src\util\key_file.cpp
  src\util\rate_limiter.cpp
  src\crypto\x25519.cpp
  src\crypto\hkdf.cpp
  src\crypto\chunk_hash.cpp
  src\crypto\merkle_tree.cpp
  src\crypto\signed_message.cpp
  src\tls\crypto_provider.cpp
  src\tls\ed25519_core.cpp
  src\tls\ed25519_verifier.cpp
  src\tls\handshake_token_key.cpp
  src\tls\address_token_store.cpp
  src\tls\replay_window.cpp
  src\address_lookup\pkarr_server.cpp
  src\collection\model_manifest.cpp
  src\collection\parallel_downloader.cpp
  src\collection\shard_state_store.cpp
  third_party\openssl\src\evp_stub.cpp
) do (
  echo   compile %%F
  cl %CXXFLAGS% %%F /c /Fo:build\base_%%~nF.obj >build\err_base_%%~nF.txt 2>&1
  if errorlevel 1 (
    echo FAILED: %%F
    type build\err_base_%%~nF.txt
    exit /b 1
  )
  set "BASE_OBJS=!BASE_OBJS! build\base_%%~nF.obj"
)
lib /NOLOGO /OUT:"build\linoh-base.lib" %BASE_OBJS%
echo.

echo ============================================================================
echo  Building linoh-relay.lib  Crate 4: relay client/server/tls_channel/access_control
echo ============================================================================

set "RELAY_OBJS="
for %%F in (
  src\relay\client.cpp
  src\relay\server.cpp
  src\relay\tls_channel.cpp
  src\relay\tcp_fallback.cpp
  src\relay\access_control.cpp
) do (
  echo   compile %%F
  cl %CXXFLAGS% %%F /c /Fo:build\relay_%%~nF.obj >build\err_relay_%%~nF.txt 2>&1
  if errorlevel 1 (
    echo FAILED: %%F
    type build\err_relay_%%~nF.txt
    exit /b 1
  )
  set "RELAY_OBJS=!RELAY_OBJS! build\relay_%%~nF.obj"
)
lib /NOLOGO /OUT:"build\linoh-relay.lib" %RELAY_OBJS%
echo.

echo ============================================================================
echo  Build Summary
echo ============================================================================
dir "build\linoh.lib"
dir "build\linoh-base.lib"
dir "build\linoh-relay.lib"
dir "build\linoh_zstd.lib"
echo.
echo Build completed successfully.
endlocal
