@echo off
REM ============================================================================
REM  linoh ??????
REM  ???? MSVC ??? (???????)
REM ============================================================================
setlocal enabledelayedexpansion

REM --- ?? vcvarsall.bat ---
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
    REM Fallback: try common paths
    for %%E in (Community Professional Enterprise BuildTools) do (
        if not exist "%VCVARSALL%" (
            if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat" (
                set "VCVARSALL=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat"
            )
        )
    )
)

if not exist "%VCVARSALL%" (
    echo ERROR: Could not find vcvarsall.bat. Please install Visual Studio with C++ tools.
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

set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO /DLINOH_COMPILE_LOG_LEVEL=2 /D_WIN32_WINNT=0x0600 /DNTDDI_VERSION=0x06000000 /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include /Ithird_party\zstd"

echo ============================================================================
echo  Building linoh-base.lib  Crate 1: base + crypto + tls + util
echo ============================================================================

set "BASE_OBJS="
for %%F in (
  src\base\key.cpp
  src\base\endpoint_addr.cpp
  src\crypto\x25519.cpp
  src\crypto\hkdf.cpp
  src\crypto\chunk_hash.cpp
  src\crypto\merkle_tree.cpp
  src\crypto\signed_message.cpp
  src\protocol\replay_protection.cpp
  src\tls\crypto_provider.cpp
  src\tls\ed25519_core.cpp
  src\tls\ed25519_verifier.cpp
  src\tls\handshake_token_key.cpp
  src\tls\replay_window.cpp
  src\tls\address_token_store.cpp
  src\util\crypto.cpp
  src\util\rate_limiter.cpp
  src\util\atomic_write.cpp
  src\util\crc32.cpp
  src\util\file_permission.cpp
  src\util\key_file.cpp
  src\collection\model_manifest.cpp
  src\collection\parallel_downloader.cpp
  src\collection\shard_state_store.cpp
  src\endpoint\peer_error_tracker.cpp
  src\endpoint\connection_monitor.cpp
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

echo   link linoh-base.lib
lib /NOLOGO /OUT:"build\linoh-base.lib" %BASE_OBJS%
echo.

echo ============================================================================
echo  Building linoh_zstd.lib  V3.4: vendored zstd compression (C sources)
echo ============================================================================

set "ZSTD_CFLAGS=/TC /O2 /MD /utf-8 /Ithird_party\zstd /Ithird_party\zstd\common /Ithird_party\zstd\compress /Ithird_party\zstd\decompress /Ithird_party\zstd\dictBuilder /DZSTD_STATIC_LINKING_ONLY /DZSTD_LEGACY_SUPPORT=0"

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
  third_party\zstd\compress\zstdmt_compress.c
  third_party\zstd\compress\zstd_compress.c
  third_party\zstd\compress\zstd_compress_literals.c
  third_party\zstd\compress\zstd_compress_sequences.c
  third_party\zstd\compress\zstd_compress_superblock.c
  third_party\zstd\compress\zstd_double_fast.c
  third_party\zstd\compress\zstd_fast.c
  third_party\zstd\compress\zstd_lazy.c
  third_party\zstd\compress\zstd_ldm.c
  third_party\zstd\compress\zstd_opt.c
  third_party\zstd\decompress\huf_decompress.c
  third_party\zstd\decompress\zstd_ddict.c
  third_party\zstd\decompress\zstd_decompress.c
  third_party\zstd\decompress\zstd_decompress_block.c
  third_party\zstd\dictBuilder\cover.c
  third_party\zstd\dictBuilder\divsufsort.c
  third_party\zstd\dictBuilder\fastcover.c
  third_party\zstd\dictBuilder\zdict.c
) do (
  echo   compile %%F
  cl %ZSTD_CFLAGS% %%F /c /Fo:build\zstd_%%~nF.obj >build\err_zstd_%%~nF.txt 2>&1
  if errorlevel 1 (
    echo FAILED: %%F
    type build\err_zstd_%%~nF.txt
    exit /b 1
  )
  set "ZSTD_OBJS=!ZSTD_OBJS! build\zstd_%%~nF.obj"
)

echo   link linoh_zstd.lib
lib /NOLOGO /OUT:"build\linoh_zstd.lib" %ZSTD_OBJS%
echo.

echo ============================================================================
echo  Building linoh.lib  Crate 2: endpoint + net + protocol + linoh_c
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
  src\tls\crypto_level.cpp
  src\protocol\multipath_selector.cpp
  src\protocol\multipath_coordinated_selector.cpp
  src\net\mtu.cpp
  src\nat\ice_candidate.cpp
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
echo  Building linoh-relay.lib  Crate 3: relay client/server/tls_channel/access_control
echo ============================================================================

set "RELAY_OBJS="
for %%F in (
  src\relay\client.cpp
  src\relay\server.cpp
  src\relay\tls_channel.cpp
  src\relay\access_control.cpp
  src\relay\tcp_fallback.cpp
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

echo   link linoh-relay.lib
lib /NOLOGO /OUT:"build\linoh-relay.lib" %RELAY_OBJS%
echo.

echo ============================================================================
echo  Building linoh-dns-server.lib  Crate 4: pkarr DNS server
echo ============================================================================

set "DNS_OBJS="
for %%F in (
  src\address_lookup\pkarr_server.cpp
) do (
  echo   compile %%F
  cl %CXXFLAGS% %%F /c /Fo:build\dns_%%~nF.obj >build\err_dns_%%~nF.txt 2>&1
  if errorlevel 1 (
    echo FAILED: %%F
    type build\err_dns_%%~nF.txt
    exit /b 1
  )
  set "DNS_OBJS=!DNS_OBJS! build\dns_%%~nF.obj"
)

echo   link linoh-dns-server.lib
lib /NOLOGO /OUT:"build\linoh-dns-server.lib" %DNS_OBJS%
echo.

REM ============================================================================
REM P-LOG-1: 测试/示例构建保留 Debug/Trace 日志
REM 部分测试通过 CerrCapture 捕获 std::cerr 断言 LINOH_DEBUG/INFO 输出内容
REM (test_loss_recovery_instrumentation / test_tracing_span / test_oos_active_notify 等)，
REM 编译期剥离会破坏这些断言。库 (.lib) 已用 /DLINOH_COMPILE_LOG_LEVEL=2 剥离热路径
REM Debug/Trace，生产部署使用库即可获得性能优化；测试需要完整日志才能验证埋点。
REM ============================================================================
set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO /D_WIN32_WINNT=0x0600 /DNTDDI_VERSION=0x06000000 /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include"

echo ============================================================================
echo  Building examples
echo ============================================================================

echo   linoh_api_server.cpp
cl %CXXFLAGS% examples\linoh_api_server.cpp /c /Fo:build\linoh_api_server.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\linoh_api_server.exe" "build\linoh_api_server.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   linoh_api_client.cpp
cl %CXXFLAGS% examples\linoh_api_client.cpp /c /Fo:build\linoh_api_client.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\linoh_api_client.exe" "build\linoh_api_client.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   linoh_echo_server.cpp
cl %CXXFLAGS% examples\linoh_echo_server.cpp /c /Fo:build\linoh_echo_server.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\linoh_echo_server.exe" "build\linoh_echo_server.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   linoh_echo_client.cpp
cl %CXXFLAGS% examples\linoh_echo_client.cpp /c /Fo:build\linoh_echo_client.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\linoh_echo_client.exe" "build\linoh_echo_client.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   relay_server_main.cpp  independent: links only linoh-relay.lib + linoh-base.lib
cl %CXXFLAGS% examples\relay_server_main.cpp /c /Fo:build\relay_server_main.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\linoh-relay-server.exe" "build\relay_server_main.obj" "build\linoh-relay.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   pkarr_dns_server_main.cpp  independent: links only linoh-dns-server.lib + linoh-base.lib
cl %CXXFLAGS% examples\pkarr_dns_server_main.cpp /c /Fo:build\pkarr_dns_server_main.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\linoh-dns-server.exe" "build\pkarr_dns_server_main.obj" "build\linoh-dns-server.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   linoh_rpc_example.cpp
cl %CXXFLAGS% examples\linoh_rpc_example.cpp /c /Fo:build\linoh_rpc_example.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\linoh_rpc_example.exe" "build\linoh_rpc_example.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo.
echo ============================================================================
echo  Building tests
echo ============================================================================

echo   test_1rtt_diag.cpp
cl %CXXFLAGS% test_1rtt_diag.cpp /c /Fo:build\test_1rtt_diag.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_1rtt_diag.exe" "build\test_1rtt_diag.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_zerortt.cpp
cl %CXXFLAGS% tests\test_zerortt.cpp /c /Fo:build\test_zerortt.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_zerortt.exe" "build\test_zerortt.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_phase4_integration.cpp
cl %CXXFLAGS% tests\test_phase4_integration.cpp /c /Fo:build\test_phase4.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_phase4.exe" "build\test_phase4.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_state_machine.cpp
cl %CXXFLAGS% tests\test_state_machine.cpp /c /Fo:build\test_state_machine.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_state_machine.exe" "build\test_state_machine.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_relay_server.cpp
cl %CXXFLAGS% tests\test_relay_server.cpp /c /Fo:build\test_relay_server.obj 2>build_test_err.txt 1>build_test_out.txt
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_relay_server.exe" "build\test_relay_server.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_x25519_hkdf.cpp
cl %CXXFLAGS% tests\test_x25519_hkdf.cpp /c /Fo:build\test_x25519_hkdf.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_x25519_hkdf.exe" "build\test_x25519_hkdf.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_key_schedule.cpp
cl %CXXFLAGS% tests\test_key_schedule.cpp /c /Fo:build\test_key_schedule.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_key_schedule.exe" "build\test_key_schedule.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_handshake_msg.cpp
cl %CXXFLAGS% tests\test_handshake_msg.cpp /c /Fo:build\test_handshake_msg.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_handshake_msg.exe" "build\test_handshake_msg.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_tls13_handshake.cpp
cl %CXXFLAGS% tests\test_tls13_handshake.cpp /c /Fo:build\test_tls13_handshake.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_tls13_handshake.exe" "build\test_tls13_handshake.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_connection_tls13.cpp
cl %CXXFLAGS% tests\test_connection_tls13.cpp /c /Fo:build\test_connection_tls13.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_connection_tls13.exe" "build\test_connection_tls13.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_application_message.cpp
cl %CXXFLAGS% tests\test_application_message.cpp /c /Fo:build\test_application_message.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_application_message.exe" "build\test_application_message.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_return_address.cpp
cl %CXXFLAGS% tests\test_return_address.cpp /c /Fo:build\test_return_address.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_return_address.exe" "build\test_return_address.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_direct_return_manager.cpp
cl %CXXFLAGS% tests\test_direct_return_manager.cpp /c /Fo:build\test_direct_return_manager.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_direct_return_manager.exe" "build\test_direct_return_manager.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_direct_return_e2e.cpp  v3.2.1 P1-4 Direct Return Path e2e
cl %CXXFLAGS% tests\test_direct_return_e2e.cpp /c /Fo:build\test_direct_return_e2e.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_direct_return_e2e.exe" "build\test_direct_return_e2e.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_congestion_auto_switch.cpp  v3.3.0 BBR v2 default + cross-domain auto
cl %CXXFLAGS% tests\test_congestion_auto_switch.cpp /c /Fo:build\test_congestion_auto_switch.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_congestion_auto_switch.exe" "build\test_congestion_auto_switch.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_zero_copy_pipeline.cpp  v3.3.0 Zero-Copy transport pipeline
cl %CXXFLAGS% tests\test_zero_copy_pipeline.cpp /c /Fo:build\test_zero_copy_pipeline.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_zero_copy_pipeline.exe" "build\test_zero_copy_pipeline.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_fec_simd.cpp  v3.3.0 FEC SIMD acceleration + adaptive recovery
cl %CXXFLAGS% tests\test_fec_simd.cpp /c /Fo:build\test_fec_simd.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_fec_simd.exe" "build\test_fec_simd.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_connection_stability.cpp  v3.3.0 connection stability adaptive enhancement
cl %CXXFLAGS% tests\test_connection_stability.cpp /c /Fo:build\test_connection_stability.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_connection_stability.exe" "build\test_connection_stability.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_event_bus.cpp  v3.4 EventBus coalesce + dual-queue backpressure
cl %CXXFLAGS% tests\test_event_bus.cpp /c /Fo:build\test_event_bus.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_event_bus.exe" "build\test_event_bus.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_session_id.cpp  v3.4 SessionId UUID v4
cl %CXXFLAGS% tests\test_session_id.cpp /c /Fo:build\test_session_id.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_session_id.exe" "build\test_session_id.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_session_deduper.cpp  v3.4 SessionDeduper LRU
cl %CXXFLAGS% tests\test_session_deduper.cpp /c /Fo:build\test_session_deduper.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_session_deduper.exe" "build\test_session_deduper.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_compression.cpp  v3.4 zstd compression
cl %CXXFLAGS% tests\test_compression.cpp /c /Fo:build\test_compression.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_compression.exe" "build\test_compression.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_message_session_id.cpp  v3.4 P4-4 ApplicationMessage + SessionId integration
cl %CXXFLAGS% tests\test_message_session_id.cpp /c /Fo:build\test_message_session_id.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_message_session_id.exe" "build\test_message_session_id.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_message_compression.cpp  v3.4 P4-5 ApplicationMessage + zstd compression integration
cl %CXXFLAGS% tests\test_message_compression.cpp /c /Fo:build\test_message_compression.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_message_compression.exe" "build\test_message_compression.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_capabilities.cpp  v3.5 P5-A node capabilities probe
cl %CXXFLAGS% tests\test_capabilities.cpp /c /Fo:build\test_capabilities.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_capabilities.exe" "build\test_capabilities.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_addr_info.cpp  v4.0.0 M18 addr info level exchange
cl %CXXFLAGS% tests\test_addr_info.cpp /c /Fo:build\test_addr_info.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_addr_info.exe" "build\test_addr_info.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_connect_policy.cpp  v4.0.1 M19 connect policy direct first
cl %CXXFLAGS% tests\test_connect_policy.cpp /c /Fo:build\test_connect_policy.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_connect_policy.exe" "build\test_connect_policy.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_shard_bitfield.cpp  v4.0.2 M20 shard availability bitfield + RLE
cl %CXXFLAGS% tests\test_shard_bitfield.cpp /c /Fo:build\test_shard_bitfield.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_shard_bitfield.exe" "build\test_shard_bitfield.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_ed25519_auth.cpp  v4.0.3 M15 Ed25519 challenge-response auth
cl %CXXFLAGS% tests\test_ed25519_auth.cpp /c /Fo:build\test_ed25519_auth.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_ed25519_auth.exe" "build\test_ed25519_auth.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_connection_migration.cpp  v4.0.4 M22 connection migration coordinator
cl %CXXFLAGS% tests\test_connection_migration.cpp /c /Fo:build\test_connection_migration.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_connection_migration.exe" "build\test_connection_migration.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_traffic_priority.cpp  v4.0.5 M23 traffic priority QoS + WFQ
cl %CXXFLAGS% tests\test_traffic_priority.cpp /c /Fo:build\test_traffic_priority.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_traffic_priority.exe" "build\test_traffic_priority.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_event_loop.cpp  v4.3.0 M7 select! event loop + EventSource
cl %CXXFLAGS% tests\test_event_loop.cpp /c /Fo:build\test_event_loop.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_event_loop.exe" "build\test_event_loop.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_bandwidth_tier_strategy.cpp  v4.3.0 M16 bandwidth tier 3-key peer sort
cl %CXXFLAGS% tests\test_bandwidth_tier_strategy.cpp /c /Fo:build\test_bandwidth_tier_strategy.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_bandwidth_tier_strategy.exe" "build\test_bandwidth_tier_strategy.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_progress_report.cpp  v4.3.0 M21 double-layer progress report frame
cl %CXXFLAGS% tests\test_progress_report.cpp /c /Fo:build\test_progress_report.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_progress_report.exe" "build\test_progress_report.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_capi_session_compress.cpp  v3.5 P5-B C-API SessionId + compression
cl %CXXFLAGS% tests\test_capi_session_compress.cpp /c /Fo:build\test_capi_session_compress.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_capi_session_compress.exe" "build\test_capi_session_compress.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_event_bus_cross_domain.cpp  v3.5 P5-C EventBus x ControlPlane cross-domain gossip
cl %CXXFLAGS% tests\test_event_bus_cross_domain.cpp /c /Fo:build\test_event_bus_cross_domain.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_event_bus_cross_domain.exe" "build\test_event_bus_cross_domain.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_packet_number.cpp
cl %CXXFLAGS% tests\test_packet_number.cpp /c /Fo:build\test_packet_number.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_packet_number.exe" "build\test_packet_number.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_stream_close_frame.cpp
cl %CXXFLAGS% tests\test_stream_close_frame.cpp /c /Fo:build\test_stream_close_frame.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_stream_close_frame.exe" "build\test_stream_close_frame.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_pto_early_retransmit.cpp
cl %CXXFLAGS% tests\test_pto_early_retransmit.cpp /c /Fo:build\test_pto_early_retransmit.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_pto_early_retransmit.exe" "build\test_pto_early_retransmit.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_replay_window.cpp
cl %CXXFLAGS% tests\test_replay_window.cpp /c /Fo:build\test_replay_window.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_replay_window.exe" "build\test_replay_window.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_secure_buffer.cpp
cl %CXXFLAGS% tests\test_secure_buffer.cpp /c /Fo:build\test_secure_buffer.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_secure_buffer.exe" "build\test_secure_buffer.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_constant_time.cpp
cl %CXXFLAGS% tests\test_constant_time.cpp /c /Fo:build\test_constant_time.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_constant_time.exe" "build\test_constant_time.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_aead_nonce.cpp
cl %CXXFLAGS% tests\test_aead_nonce.cpp /c /Fo:build\test_aead_nonce.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_aead_nonce.exe" "build\test_aead_nonce.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_on_close_dedup.cpp
cl %CXXFLAGS% tests\test_on_close_dedup.cpp /c /Fo:build\test_on_close_dedup.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_on_close_dedup.exe" "build\test_on_close_dedup.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_heartbeat.cpp
cl %CXXFLAGS% tests\test_heartbeat.cpp /c /Fo:build\test_heartbeat.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_heartbeat.exe" "build\test_heartbeat.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_rpc_pool.cpp
cl %CXXFLAGS% tests\test_rpc_pool.cpp /c /Fo:build\test_rpc_pool.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_rpc_pool.exe" "build\test_rpc_pool.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_session_ticket.cpp
cl %CXXFLAGS% tests\test_session_ticket.cpp /c /Fo:build\test_session_ticket.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_session_ticket.exe" "build\test_session_ticket.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_async_api.cpp
cl %CXXFLAGS% tests\test_async_api.cpp /c /Fo:build\test_async_api.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_async_api.exe" "build\test_async_api.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_compressed_msg.cpp
cl %CXXFLAGS% tests\test_compressed_msg.cpp /c /Fo:build\test_compressed_msg.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_compressed_msg.exe" "build\test_compressed_msg.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_key_update.cpp
cl %CXXFLAGS% tests\test_key_update.cpp /c /Fo:build\test_key_update.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_key_update.exe" "build\test_key_update.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_four_tuple.cpp
cl %CXXFLAGS% tests\test_four_tuple.cpp /c /Fo:build\test_four_tuple.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_four_tuple.exe" "build\test_four_tuple.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_address_token_store.cpp
cl %CXXFLAGS% tests\test_address_token_store.cpp /c /Fo:build\test_address_token_store.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_address_token_store.exe" "build\test_address_token_store.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_close_immediate.cpp
cl %CXXFLAGS% tests\test_close_immediate.cpp /c /Fo:build\test_close_immediate.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_close_immediate.exe" "build\test_close_immediate.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_path_abandon.cpp
cl %CXXFLAGS% tests\test_path_abandon.cpp /c /Fo:build\test_path_abandon.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_path_abandon.exe" "build\test_path_abandon.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_stun.cpp
cl %CXXFLAGS% tests\test_stun.cpp /c /Fo:build\test_stun.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_stun.exe" "build\test_stun.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_net_report.cpp
cl %CXXFLAGS% tests\test_net_report.cpp /c /Fo:build\test_net_report.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_net_report.exe" "build\test_net_report.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_happy_eyeballs.cpp
cl %CXXFLAGS% tests\test_happy_eyeballs.cpp /c /Fo:build\test_happy_eyeballs.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_happy_eyeballs.exe" "build\test_happy_eyeballs.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_path_strategy.cpp
cl %CXXFLAGS% tests\test_path_strategy.cpp /c /Fo:build\test_path_strategy.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_path_strategy.exe" "build\test_path_strategy.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_v470_path_api.cpp  v4.7.0 Path Observation API + PP strategies
cl %CXXFLAGS% tests\test_v470_path_api.cpp /c /Fo:build\test_v470_path_api.obj >build\err_test_v470_path_api.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_test_v470_path_api.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_v470_path_api.exe" "build\test_v470_path_api.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_v480_security.cpp  v4.8.0 IncomingFilter + AccessControl + external_addr + IPv6 deprecated
cl %CXXFLAGS% tests\test_v480_security.cpp /c /Fo:build\test_v480_security.obj >build\err_test_v480_security.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_test_v480_security.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_v480_security.exe" "build\test_v480_security.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_v480_rate_limit_bench.cpp  T-LP3-007 RateLimitFilter benchmark
cl %CXXFLAGS% tests\test_v480_rate_limit_bench.cpp /c /Fo:build\test_v480_rate_limit_bench.obj >build\err_test_v480_rate_limit_bench.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_test_v480_rate_limit_bench.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_v480_rate_limit_bench.exe" "build\test_v480_rate_limit_bench.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_v500_frames.cpp  v5.0.0 T-LP4-001 SESSION_TICKET + ZERO_RTT_DATA frames
cl %CXXFLAGS% tests\test_v500_frames.cpp /c /Fo:build\test_v500_frames.obj >build\err_test_v500_frames.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_test_v500_frames.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_v500_frames.exe" "build\test_v500_frames.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_v500_session_cache.cpp  v5.0.0 T-LP4-003 Session Cache
cl %CXXFLAGS% tests\test_v500_session_cache.cpp /c /Fo:build\test_v500_session_cache.obj >build\err_test_v500_session_cache.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_test_v500_session_cache.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_v500_session_cache.exe" "build\test_v500_session_cache.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_v500_qad_connection.cpp  v5.0.0 T-LP4-008 QAD Connection + T-LP4-007 Capabilities
cl %CXXFLAGS% tests\test_v500_qad_connection.cpp /c /Fo:build\test_v500_qad_connection.obj >build\err_test_v500_qad_connection.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_test_v500_qad_connection.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_v500_qad_connection.exe" "build\test_v500_qad_connection.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_v500_path_probe.cpp  v5.0.0 T-LP4-005 relay PATH_CHALLENGE forward
cl %CXXFLAGS% tests\test_v500_path_probe.cpp /c /Fo:build\test_v500_path_probe.obj >build\err_test_v500_path_probe.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_test_v500_path_probe.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_v500_path_probe.exe" "build\test_v500_path_probe.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_v500_bidir_holepunch.cpp  v5.0.0 T-LP4-004 Bidirectional Holepuncher
cl %CXXFLAGS% tests\test_v500_bidir_holepunch.cpp /c /Fo:build\test_v500_bidir_holepunch.obj >build\err_test_v500_bidir_holepunch.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_test_v500_bidir_holepunch.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_v500_bidir_holepunch.exe" "build\test_v500_bidir_holepunch.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_v600_crypto_provider.cpp  v6.0.0 T-LP5-003 CryptoProvider trait
cl %CXXFLAGS% tests\test_v600_crypto_provider.cpp /c /Fo:build\test_v600_crypto_provider.obj >build\err_test_v600_crypto_provider.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_test_v600_crypto_provider.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_v600_crypto_provider.exe" "build\test_v600_crypto_provider.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_access_control.cpp
cl %CXXFLAGS% tests\test_access_control.cpp /c /Fo:build\test_access_control.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_access_control.exe" "build\test_access_control.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_rate_limiter.cpp
cl %CXXFLAGS% tests\test_rate_limiter.cpp /c /Fo:build\test_rate_limiter.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_rate_limiter.exe" "build\test_rate_limiter.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_holepuncher.cpp
cl %CXXFLAGS% tests\test_holepuncher.cpp /c /Fo:build\test_holepuncher.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_holepuncher.exe" "build\test_holepuncher.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_custom_transport.cpp
cl %CXXFLAGS% tests\test_custom_transport.cpp /c /Fo:build\test_custom_transport.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_custom_transport.exe" "build\test_custom_transport.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_dns_fallback.cpp
cl %CXXFLAGS% tests\test_dns_fallback.cpp /c /Fo:build\test_dns_fallback.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_dns_fallback.exe" "build\test_dns_fallback.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_multimodal_channel.cpp  P5-A-1
cl %CXXFLAGS% tests\test_multimodal_channel.cpp /c /Fo:build\test_multimodal_channel.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_multimodal_channel.exe" "build\test_multimodal_channel.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_control_channel.cpp  P5-A-2
cl %CXXFLAGS% tests\test_control_channel.cpp /c /Fo:build\test_control_channel.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_control_channel.exe" "build\test_control_channel.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_tensor_stream.cpp  P5-A-3
cl %CXXFLAGS% tests\test_tensor_stream.cpp /c /Fo:build\test_tensor_stream.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_tensor_stream.exe" "build\test_tensor_stream.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_tensor_stream_c_api.cpp  v5.1.0 T-LA
cl %CXXFLAGS% tests\test_tensor_stream_c_api.cpp /c /Fo:build\test_tensor_stream_c_api.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_tensor_stream_c_api.exe" "build\test_tensor_stream_c_api.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_tensor_stream_timeout.cpp  v1.5 P1-3
cl %CXXFLAGS% tests\test_tensor_stream_timeout.cpp /c /Fo:build\test_tensor_stream_timeout.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_tensor_stream_timeout.exe" "build\test_tensor_stream_timeout.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_linoh_c_alpn_override.cpp  v1.5 P1-1
cl %CXXFLAGS% tests\test_linoh_c_alpn_override.cpp /c /Fo:build\test_linoh_c_alpn_override.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_linoh_c_alpn_override.exe" "build\test_linoh_c_alpn_override.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_linoh_c_lifecycle.cpp  v1.5 P1-2
cl %CXXFLAGS% tests\test_linoh_c_lifecycle.cpp /c /Fo:build\test_linoh_c_lifecycle.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_linoh_c_lifecycle.exe" "build\test_linoh_c_lifecycle.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_pp_multimodal_chain.cpp  v1.5.0.2 P5-A-1 PP chain multimodal ALPN
cl %CXXFLAGS% tests\test_pp_multimodal_chain.cpp /c /Fo:build\test_pp_multimodal_chain.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_pp_multimodal_chain.exe" "build\test_pp_multimodal_chain.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_loss_recovery_p2.cpp  v1.5 P2-1+P2-3
cl %CXXFLAGS% tests\test_loss_recovery_p2.cpp /c /Fo:build\test_loss_recovery_p2.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_loss_recovery_p2.exe" "build\test_loss_recovery_p2.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_loss_recovery_instrumentation.cpp  v1.5.0.2.6 loss_recovery instrumentation
cl %CXXFLAGS% tests\test_loss_recovery_instrumentation.cpp /c /Fo:build\test_loss_recovery_instrumentation.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_loss_recovery_instrumentation.exe" "build\test_loss_recovery_instrumentation.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_build_fin_only_packet.cpp  v1.5 P0-2
cl %CXXFLAGS% tests\test_build_fin_only_packet.cpp /c /Fo:build\test_build_fin_only_packet.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_build_fin_only_packet.exe" "build\test_build_fin_only_packet.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_retransmit_oos_recovery.cpp  v1.5.0.1 P0-1
cl %CXXFLAGS% tests\test_retransmit_oos_recovery.cpp /c /Fo:build\test_retransmit_oos_recovery.obj
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_retransmit_oos_recovery.exe" "build\test_retransmit_oos_recovery.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE

echo   tests\test_payload_audit.cpp  v1.5.0.1 P0-1 observability
cl %CXXFLAGS% tests\test_payload_audit.cpp /c /Fo:build\test_payload_audit.obj
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_payload_audit.exe" "build\test_payload_audit.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE

echo   tests\test_periodic_fc_emission.cpp  v1.5.0.1 P3-1
cl %CXXFLAGS% tests\test_periodic_fc_emission.cpp /c /Fo:build\test_periodic_fc_emission.obj
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_periodic_fc_emission.exe" "build\test_periodic_fc_emission.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE

echo   tests\test_iw10.cpp  v1.5.0.1 P2-2 RFC 6928
cl %CXXFLAGS% tests\test_iw10.cpp /c /Fo:build\test_iw10.obj
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_iw10.exe" "build\test_iw10.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE

echo   tests\test_fec.cpp  P5-B-1
cl %CXXFLAGS% tests\test_fec.cpp /c /Fo:build\test_fec.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_fec.exe" "build\test_fec.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_fec_group.cpp  v1.5.0.2 P5-B-1 Step 2 FEC Group
cl %CXXFLAGS% tests\test_fec_group.cpp /c /Fo:build\test_fec_group.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_fec_group.exe" "build\test_fec_group.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_mtu_negotiation.cpp  v1.5.0.2 Step 3 MTU negotiation
cl %CXXFLAGS% tests\test_mtu_negotiation.cpp /c /Fo:build\test_mtu_negotiation.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_mtu_negotiation.exe" "build\test_mtu_negotiation.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_crypto_negotiation.cpp  v1.5.0.2 Step 4 CryptoLevel negotiation
cl %CXXFLAGS% tests\test_crypto_negotiation.cpp /c /Fo:build\test_crypto_negotiation.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_crypto_negotiation.exe" "build\test_crypto_negotiation.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_crypto_level.cpp  P5-B-2
cl %CXXFLAGS% tests\test_crypto_level.cpp /c /Fo:build\test_crypto_level.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_crypto_level.exe" "build\test_crypto_level.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_c_api_recovery.cpp  v1.5.0.2.3 cluster C-API recovery (12 APIs)
cl %CXXFLAGS% tests\test_c_api_recovery.cpp /c /Fo:build\test_c_api_recovery.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_c_api_recovery.exe" "build\test_c_api_recovery.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_oos_active_notify.cpp  v1.5.0.3 F3 OOS active notify API
cl %CXXFLAGS% tests\test_oos_active_notify.cpp /c /Fo:build\test_oos_active_notify.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_oos_active_notify.exe" "build\test_oos_active_notify.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_oos_active_notify.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_oos_active_notify.txt & exit /b 1 )

echo   tests\test_loss_recovery_v1504.cpp  v1.5.0.4 OOS buffer PN injection
cl %CXXFLAGS% tests\test_loss_recovery_v1504.cpp /c /Fo:build\test_loss_recovery_v1504.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_loss_recovery_v1504.exe" "build\test_loss_recovery_v1504.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_loss_recovery_v1504.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_loss_recovery_v1504.txt & exit /b 1 )

echo   tests\test_bbr_v2_state_machine.cpp  v2.0 BBR v2 state machine
cl %CXXFLAGS% tests\test_bbr_v2_state_machine.cpp /c /Fo:build\test_bbr_v2_state_machine.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_bbr_v2_state_machine.exe" "build\test_bbr_v2_state_machine.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_bbr_v2_state_machine.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_bbr_v2_state_machine.txt & exit /b 1 )

echo   tests\test_loss_recovery_v1505.cpp  v1.5.0.5 Plan A+ OOS_PN_FRAME
cl %CXXFLAGS% tests\test_loss_recovery_v1505.cpp /c /Fo:build\test_loss_recovery_v1505.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_loss_recovery_v1505.exe" "build\test_loss_recovery_v1505.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_loss_recovery_v1505.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_loss_recovery_v1505.txt & exit /b 1 )

echo   tests\test_loss_recovery_v1507.cpp  v1.5.0.7 OOS_PN trigger chain (ISSUE T06 fix)
cl %CXXFLAGS% tests\test_loss_recovery_v1507.cpp /c /Fo:build\test_loss_recovery_v1507.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_loss_recovery_v1507.exe" "build\test_loss_recovery_v1507.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_loss_recovery_v1507.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_loss_recovery_v1507.txt & exit /b 1 )

echo   tests\test_loss_recovery_v1508.cpp  v1.5.0.8 Connection-LossDetector OOS_PN sync (ISSUE T07 fix)
cl %CXXFLAGS% tests\test_loss_recovery_v1508.cpp /c /Fo:build\test_loss_recovery_v1508.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_loss_recovery_v1508.exe" "build\test_loss_recovery_v1508.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_loss_recovery_v1508.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_loss_recovery_v1508.txt & exit /b 1 )

echo   tests\test_loss_recovery_v1509.cpp  v1.5.0.9 stream_ranges precise lookup + cwnd suppress (ISSUE T08 fix)
cl %CXXFLAGS% tests\test_loss_recovery_v1509.cpp /c /Fo:build\test_loss_recovery_v1509.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
REM v1.5.0.9 obj ???? iostream ???std::cerr.rdbuf + std::stringstream??
REM ????? MSVCRT/UCRT ????? LNK2005 ????
link /NOLOGO /OUT:"build\test_loss_recovery_v1509.exe" "build\test_loss_recovery_v1509.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_loss_recovery_v1509.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_loss_recovery_v1509.txt & exit /b 1 )

echo   tests\test_loss_recovery_v1510.cpp  v1.5.0.10 OOS_PN chain diagnostics + tolerance range (ISSUE T09 fix)
cl %CXXFLAGS% tests\test_loss_recovery_v1510.cpp /c /Fo:build\test_loss_recovery_v1510.obj >build\err_cl_test_loss_recovery_v1510.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_loss_recovery_v1510.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_loss_recovery_v1510.exe" "build\test_loss_recovery_v1510.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_loss_recovery_v1510.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_loss_recovery_v1510.txt & exit /b 1 )

echo   tests\test_oos_pn_reliability_v1510.cpp  v1.5.0.10 OOS_PN UDP reliability mechanism (ISSUE T09 fix)
cl %CXXFLAGS% tests\test_oos_pn_reliability_v1510.cpp /c /Fo:build\test_oos_pn_reliability_v1510.obj >build\err_cl_test_oos_pn_reliability_v1510.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_oos_pn_reliability_v1510.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_oos_pn_reliability_v1510.exe" "build\test_oos_pn_reliability_v1510.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_oos_pn_reliability_v1510.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_oos_pn_reliability_v1510.txt & exit /b 1 )

echo   tests\test_loss_recovery_v1511.cpp  v1.5.0.11 StreamRange lifecycle + mark_lost audit + tolerance (ISSUE T10 fix)
cl %CXXFLAGS% tests\test_loss_recovery_v1511.cpp /c /Fo:build\test_loss_recovery_v1511.obj >build\err_cl_test_loss_recovery_v1511.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_loss_recovery_v1511.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_loss_recovery_v1511.exe" "build\test_loss_recovery_v1511.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_loss_recovery_v1511.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_loss_recovery_v1511.txt & exit /b 1 )

echo   tests\test_loss_recovery_thread_safety.cpp  v4.4.3 P92/P93 loss_recovery thread safety
cl %CXXFLAGS% tests\test_loss_recovery_thread_safety.cpp /c /Fo:build\test_loss_recovery_thread_safety.obj >build\err_cl_test_loss_recovery_thread_safety.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_loss_recovery_thread_safety.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_loss_recovery_thread_safety.exe" "build\test_loss_recovery_thread_safety.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_loss_recovery_thread_safety.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_loss_recovery_thread_safety.txt & exit /b 1 )

echo   tests\test_oos_pn_reliability_v1511.cpp  v1.5.0.11 UDP resend enhancement 100ms x 8 + high_priority + ACK-eliciting (ISSUE T10 fix)
cl %CXXFLAGS% tests\test_oos_pn_reliability_v1511.cpp /c /Fo:build\test_oos_pn_reliability_v1511.obj >build\err_cl_test_oos_pn_reliability_v1511.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_oos_pn_reliability_v1511.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_oos_pn_reliability_v1511.exe" "build\test_oos_pn_reliability_v1511.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_oos_pn_reliability_v1511.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_oos_pn_reliability_v1511.txt & exit /b 1 )

echo   tests\test_stream_range_lifecycle_v1511.cpp  v1.5.0.11 StreamRange lifecycle consistency (ISSUE T10 register-clean chain)
cl %CXXFLAGS% tests\test_stream_range_lifecycle_v1511.cpp /c /Fo:build\test_stream_range_lifecycle_v1511.obj >build\err_cl_test_stream_range_lifecycle_v1511.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_stream_range_lifecycle_v1511.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_stream_range_lifecycle_v1511.exe" "build\test_stream_range_lifecycle_v1511.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_stream_range_lifecycle_v1511.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_stream_range_lifecycle_v1511.txt & exit /b 1 )

echo   tests\test_resend_decoupling_v1512.cpp  v1.5.0.12 resend-build decoupling + rhythm tracking (ISSUE T11 fix)
cl %CXXFLAGS% tests\test_resend_decoupling_v1512.cpp /c /Fo:build\test_resend_decoupling_v1512.obj >build\err_cl_test_resend_decoupling_v1512.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_resend_decoupling_v1512.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_resend_decoupling_v1512.exe" "build\test_resend_decoupling_v1512.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_resend_decoupling_v1512.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_resend_decoupling_v1512.txt & exit /b 1 )

echo   tests\test_high_priority_compile_v1512.cpp  v1.5.0.12 high_priority queue compile verification (ISSUE T11 fix)
cl %CXXFLAGS% tests\test_high_priority_compile_v1512.cpp /c /Fo:build\test_high_priority_compile_v1512.obj >build\err_cl_test_high_priority_compile_v1512.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_high_priority_compile_v1512.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_high_priority_compile_v1512.exe" "build\test_high_priority_compile_v1512.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_high_priority_compile_v1512.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_high_priority_compile_v1512.txt & exit /b 1 )

echo   tests\test_stream_range_full_register_v1512.cpp  v1.5.0.12 StreamRange registration completeness (ISSUE T11 fix)
cl %CXXFLAGS% tests\test_stream_range_full_register_v1512.cpp /c /Fo:build\test_stream_range_full_register_v1512.obj >build\err_cl_test_stream_range_full_register_v1512.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_stream_range_full_register_v1512.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_stream_range_full_register_v1512.exe" "build\test_stream_range_full_register_v1512.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_stream_range_full_register_v1512.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_stream_range_full_register_v1512.txt & exit /b 1 )

echo ============================================================================
echo  v1.6.0.1 EP tests (P0: EP frames + ALPN channels + EpChannel)
echo ============================================================================

echo   tests\test_ep_frames_v1601.cpp  v1.6.0.1 EP protocol frames + ALPN mapping + channel config
cl %CXXFLAGS% tests\test_ep_frames_v1601.cpp /c /Fo:build\test_ep_frames_v1601.obj >build\err_cl_test_ep_frames_v1601.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_ep_frames_v1601.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_ep_frames_v1601.exe" "build\test_ep_frames_v1601.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_ep_frames_v1601.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_ep_frames_v1601.txt & exit /b 1 )

echo ============================================================================
echo  v1.6.0.2 EP tests (P1: SyncPrimitives barrier/signal/all-reduce)
echo ============================================================================

echo   tests\test_sync_primitives_v1602.cpp  v1.6.0.2 sync primitives unit tests
cl %CXXFLAGS% tests\test_sync_primitives_v1602.cpp /c /Fo:build\test_sync_primitives_v1602.obj >build\err_cl_test_sync_primitives_v1602.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_sync_primitives_v1602.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_sync_primitives_v1602.exe" "build\test_sync_primitives_v1602.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_sync_primitives_v1602.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_sync_primitives_v1602.txt & exit /b 1 )

echo ============================================================================
echo  v1.6.0.3 EP tests (P2: StaticBufferPool + ZeroCopy + StaticShape)
echo ============================================================================

echo   tests\test_buffer_pool_v1603.cpp  v1.6.0.3 buffer pool unit tests
cl %CXXFLAGS% tests\test_buffer_pool_v1603.cpp /c /Fo:build\test_buffer_pool_v1603.obj >build\err_cl_test_buffer_pool_v1603.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_buffer_pool_v1603.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_buffer_pool_v1603.exe" "build\test_buffer_pool_v1603.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_buffer_pool_v1603.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_buffer_pool_v1603.txt & exit /b 1 )

echo   tests\test_static_shape_v1603.cpp  v1.6.0.3 static shape unit tests
cl %CXXFLAGS% tests\test_static_shape_v1603.cpp /c /Fo:build\test_static_shape_v1603.obj >build\err_cl_test_static_shape_v1603.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_static_shape_v1603.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_static_shape_v1603.exe" "build\test_static_shape_v1603.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_static_shape_v1603.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_static_shape_v1603.txt & exit /b 1 )

echo   tests\test_zero_copy_v1603.cpp  v1.6.0.3 zero copy path unit tests
cl %CXXFLAGS% tests\test_zero_copy_v1603.cpp /c /Fo:build\test_zero_copy_v1603.obj >build\err_cl_test_zero_copy_v1603.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_zero_copy_v1603.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_zero_copy_v1603.exe" "build\test_zero_copy_v1603.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_zero_copy_v1603.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_zero_copy_v1603.txt & exit /b 1 )

echo ============================================================================
echo  v1.6.0.4 EP tests (P3: CommPlanner + LRUHashCache + serialize)
echo ============================================================================

echo   tests\test_comm_planner_v1604.cpp  v1.6.0.4 comm planner unit tests
cl %CXXFLAGS% tests\test_comm_planner_v1604.cpp /c /Fo:build\test_comm_planner_v1604.obj >build\err_cl_test_comm_planner_v1604.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_comm_planner_v1604.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_comm_planner_v1604.exe" "build\test_comm_planner_v1604.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_comm_planner_v1604.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_comm_planner_v1604.txt & exit /b 1 )

echo   tests\test_hw_accel_v1605.cpp  v1.6.0.5 hw accel unit tests
cl %CXXFLAGS% tests\test_hw_accel_v1605.cpp /c /Fo:build\test_hw_accel_v1605.obj >build\err_cl_test_hw_accel_v1605.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_hw_accel_v1605.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_hw_accel_v1605.exe" "build\test_hw_accel_v1605.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_hw_accel_v1605.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_hw_accel_v1605.txt & exit /b 1 )

echo   tests\test_expert_balancer_v1606.cpp  v1.6.0.6 expert balancer unit tests
cl %CXXFLAGS% tests\test_expert_balancer_v1606.cpp /c /Fo:build\test_expert_balancer_v1606.obj >build\err_cl_test_expert_balancer_v1606.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_expert_balancer_v1606.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_expert_balancer_v1606.exe" "build\test_expert_balancer_v1606.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_expert_balancer_v1606.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_expert_balancer_v1606.txt & exit /b 1 )

echo   tests\test_ep_reliability_v1607.cpp  v1.6.0.7 EP reliability unit tests
cl %CXXFLAGS% tests\test_ep_reliability_v1607.cpp /c /Fo:build\test_ep_reliability_v1607.obj >build\err_cl_test_ep_reliability_v1607.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_ep_reliability_v1607.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_ep_reliability_v1607.exe" "build\test_ep_reliability_v1607.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_ep_reliability_v1607.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_ep_reliability_v1607.txt & exit /b 1 )

echo   tests\test_ep_e2e_v1608.cpp  v1.6.0.8 EP end-to-end integration tests
cl %CXXFLAGS% tests\test_ep_e2e_v1608.cpp /c /Fo:build\test_ep_e2e_v1608.obj >build\err_cl_test_ep_e2e_v1608.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_ep_e2e_v1608.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_ep_e2e_v1608.exe" "build\test_ep_e2e_v1608.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_ep_e2e_v1608.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_ep_e2e_v1608.txt & exit /b 1 )

echo   tests\test_ep_c_api.cpp  v1.6.0.1 EP C-API surface + lifecycle + loopback
cl %CXXFLAGS% tests\test_ep_c_api.cpp /c /Fo:build\test_ep_c_api.obj >build\err_cl_test_ep_c_api.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_ep_c_api.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_ep_c_api.exe" "build\test_ep_c_api.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_ep_c_api.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_ep_c_api.txt & exit /b 1 )

echo   tests\test_oos_complete_overlap_v1709.cpp  v1.7.0.9 insert_oos_merged complete-overlap fix
cl %CXXFLAGS% tests\test_oos_complete_overlap_v1709.cpp /c /Fo:build\test_oos_complete_overlap_v1709.obj >build\err_cl_test_oos_complete_overlap_v1709.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_oos_complete_overlap_v1709.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_oos_complete_overlap_v1709.exe" "build\test_oos_complete_overlap_v1709.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_oos_complete_overlap_v1709.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_oos_complete_overlap_v1709.txt & exit /b 1 )

echo ============================================================================
echo  v1.7.0.1 P0 tests (A4 network change monitoring + reholepunch)
echo ============================================================================

echo   tests\test_route_monitor.cpp  v1.7.0.1 RouteMonitor + RouteEvent
cl %CXXFLAGS% tests\test_route_monitor.cpp /c /Fo:build\test_route_monitor.obj >build\err_cl_test_route_monitor.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_route_monitor.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_route_monitor.exe" "build\test_route_monitor.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib iphlpapi.lib /SUBSYSTEM:CONSOLE >build\err_link_test_route_monitor.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_route_monitor.txt & exit /b 1 )

echo   tests\test_default_route_poller.cpp  v1.7.0.1 DefaultRoutePoller exponential backoff
cl %CXXFLAGS% tests\test_default_route_poller.cpp /c /Fo:build\test_default_route_poller.obj >build\err_cl_test_default_route_poller.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_default_route_poller.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_default_route_poller.exe" "build\test_default_route_poller.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib iphlpapi.lib /SUBSYSTEM:CONSOLE >build\err_link_test_default_route_poller.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_default_route_poller.txt & exit /b 1 )

echo   tests\test_endpoint_network_change.cpp  v1.7.0.1 Endpoint network change integration
cl %CXXFLAGS% tests\test_endpoint_network_change.cpp /c /Fo:build\test_endpoint_network_change.obj >build\err_cl_test_endpoint_network_change.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_endpoint_network_change.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_endpoint_network_change.exe" "build\test_endpoint_network_change.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib iphlpapi.lib /SUBSYSTEM:CONSOLE >build\err_link_test_endpoint_network_change.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_endpoint_network_change.txt & exit /b 1 )

echo   tests\test_v460_stability_fixes.cpp  v4.6.0 Phase 1 stability fixes (PTO clamp + TLP + on_network_change)
cl %CXXFLAGS% tests\test_v460_stability_fixes.cpp /c /Fo:build\test_v460_stability_fixes.obj >build\err_cl_test_v460_stability_fixes.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_v460_stability_fixes.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_v460_stability_fixes.exe" "build\test_v460_stability_fixes.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib iphlpapi.lib /SUBSYSTEM:CONSOLE >build\err_link_test_v460_stability_fixes.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_v460_stability_fixes.txt & exit /b 1 )

echo   tests\test_endpoint_nat_hardening.cpp  v3.6.0 P5-D-3 Endpoint NAT hardening integration
cl %CXXFLAGS% tests\test_endpoint_nat_hardening.cpp /c /Fo:build\test_endpoint_nat_hardening.obj >build\err_cl_test_endpoint_nat_hardening.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_endpoint_nat_hardening.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_endpoint_nat_hardening.exe" "build\test_endpoint_nat_hardening.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib iphlpapi.lib /SUBSYSTEM:CONSOLE >build\err_link_test_endpoint_nat_hardening.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_endpoint_nat_hardening.txt & exit /b 1 )

echo ============================================================================
echo  v1.7.0.2 P1 tests (B3 rate limiter hot update + B4 channel fairness stats)
echo ============================================================================

echo   tests\test_rate_limiter_hot_update.cpp  v1.7.0.2 B3 TokenBucket/RateLimiter set_rate
cl %CXXFLAGS% tests\test_rate_limiter_hot_update.cpp /c /Fo:build\test_rate_limiter_hot_update.obj >build\err_cl_test_rate_limiter_hot_update.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_rate_limiter_hot_update.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_rate_limiter_hot_update.exe" "build\test_rate_limiter_hot_update.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_rate_limiter_hot_update.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_rate_limiter_hot_update.txt & exit /b 1 )

echo   tests\test_channel_stats.cpp  v1.7.0.2 B4 ChannelStatsRegistry fairness
cl %CXXFLAGS% tests\test_channel_stats.cpp /c /Fo:build\test_channel_stats.obj >build\err_cl_test_channel_stats.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_channel_stats.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_channel_stats.exe" "build\test_channel_stats.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_channel_stats.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_channel_stats.txt & exit /b 1 )

echo ============================================================================
echo  v1.7.0.3 P2 tests (B2 RelayServerBuilder + embedded relay)
echo ============================================================================

echo   tests\test_relay_server_builder.cpp  v1.7.0.3 B2 RelayServerBuilder + Endpoint embedded relay
cl %CXXFLAGS% tests\test_relay_server_builder.cpp /c /Fo:build\test_relay_server_builder.obj >build\err_cl_test_relay_server_builder.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_relay_server_builder.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_relay_server_builder.exe" "build\test_relay_server_builder.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_relay_server_builder.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_relay_server_builder.txt & exit /b 1 )

echo ============================================================================
echo  v1.7.0.4 P3 tests (B7 PathStats + B8 TracingSpan)
echo ============================================================================

echo   tests\test_path_stats.cpp  v1.7.0.4 B7 PathStats/ConnectionStats/Aggregator
cl %CXXFLAGS% tests\test_path_stats.cpp /c /Fo:build\test_path_stats.obj >build\err_cl_test_path_stats.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_path_stats.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_path_stats.exe" "build\test_path_stats.obj" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_path_stats.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_path_stats.txt & exit /b 1 )

echo   tests\test_path_event.cpp  v1.7.0.4 B7/B8 PathEvent + callback dispatch
cl %CXXFLAGS% tests\test_path_event.cpp /c /Fo:build\test_path_event.obj >build\err_cl_test_path_event.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_path_event.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_path_event.exe" "build\test_path_event.obj" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_path_event.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_path_event.txt & exit /b 1 )

echo   tests\test_tracing_span.cpp  v1.7.0.4 B8 TracingSpan + LINOH_CONN_LOG/LINOH_EVENT
cl %CXXFLAGS% tests\test_tracing_span.cpp /c /Fo:build\test_tracing_span.obj >build\err_cl_test_tracing_span.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_tracing_span.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_tracing_span.exe" "build\test_tracing_span.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_tracing_span.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_tracing_span.txt & exit /b 1 )

echo   tests\test_path_migration_event_integration.cpp  v1.7.0.4 P3 B7 PathMigration+PathEvent+Aggregator integration
cl %CXXFLAGS% tests\test_path_migration_event_integration.cpp /c /Fo:build\test_path_migration_event_integration.obj >build\err_cl_test_path_migration_event_integration.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_path_migration_event_integration.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_path_migration_event_integration.exe" "build\test_path_migration_event_integration.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_path_migration_event_integration.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_path_migration_event_integration.txt & exit /b 1 )

echo  v1.7.0.5 P4 tests (C3 Empty ALPN Guard - iroh #4427)
echo   tests\test_empty_alpn_guard.cpp  v1.7.0.5 C3 connect entry empty ALPN rejection
cl %CXXFLAGS% tests\test_empty_alpn_guard.cpp /c /Fo:build\test_empty_alpn_guard.obj >build\err_cl_test_empty_alpn_guard.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_empty_alpn_guard.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_empty_alpn_guard.exe" "build\test_empty_alpn_guard.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_empty_alpn_guard.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_empty_alpn_guard.txt & exit /b 1 )

echo  v1.7.0.5 P4 tests (C8 Invalid Relay Message Guard - iroh #4389)
echo   tests\test_relay_invalid_message_guard.cpp  v1.7.0.5 C8 relay frame malformed defense
cl %CXXFLAGS% tests\test_relay_invalid_message_guard.cpp /c /Fo:build\test_relay_invalid_message_guard.obj >build\err_cl_test_relay_invalid_message_guard.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_relay_invalid_message_guard.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_relay_invalid_message_guard.exe" "build\test_relay_invalid_message_guard.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_relay_invalid_message_guard.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_relay_invalid_message_guard.txt & exit /b 1 )

echo  v1.7.0.5 P4 tests (C5 Windows Transient Recv Errors - iroh #4348)
echo   tests\test_windows_recv_errors.cpp  v1.7.0.5 C5 UDP recv transient error tolerance
cl %CXXFLAGS% tests\test_windows_recv_errors.cpp /c /Fo:build\test_windows_recv_errors.obj >build\err_cl_test_windows_recv_errors.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_windows_recv_errors.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_windows_recv_errors.exe" "build\test_windows_recv_errors.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_windows_recv_errors.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_windows_recv_errors.txt & exit /b 1 )

echo   tests\test_multipath_selector.cpp  P5-B-3
cl %CXXFLAGS% tests\test_multipath_selector.cpp /c /Fo:build\test_multipath_selector.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_multipath_selector.exe" "build\test_multipath_selector.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_mtu.cpp  P5-B-4
cl %CXXFLAGS% tests\test_mtu.cpp /c /Fo:build\test_mtu.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_mtu.exe" "build\test_mtu.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_sync.cpp  P5-C-1
cl %CXXFLAGS% tests\test_sync.cpp /c /Fo:build\test_sync.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_sync.exe" "build\test_sync.obj" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_stat_trackers.cpp  P5-C-2
cl %CXXFLAGS% tests\test_stat_trackers.cpp /c /Fo:build\test_stat_trackers.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_stat_trackers.exe" "build\test_stat_trackers.obj" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_task_pool.cpp  P5-C-3
cl %CXXFLAGS% tests\test_task_pool.cpp /c /Fo:build\test_task_pool.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_task_pool.exe" "build\test_task_pool.obj" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_ports.cpp  P5-C-4
cl %CXXFLAGS% tests\test_ports.cpp /c /Fo:build\test_ports.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_ports.exe" "build\test_ports.obj" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_ice_candidate.cpp  P5-D-1
cl %CXXFLAGS% tests\test_ice_candidate.cpp /c /Fo:build\test_ice_candidate.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_ice_candidate.exe" "build\test_ice_candidate.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_ice_session.cpp  P5-D-2
cl %CXXFLAGS% tests\test_ice_session.cpp /c /Fo:build\test_ice_session.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_ice_session.exe" "build\test_ice_session.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_cgn_detector.cpp  P5-D-3
cl %CXXFLAGS% tests\test_cgn_detector.cpp /c /Fo:build\test_cgn_detector.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_cgn_detector.exe" "build\test_cgn_detector.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_dual_stack.cpp  P5-D-4
cl %CXXFLAGS% tests\test_dual_stack.cpp /c /Fo:build\test_dual_stack.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_dual_stack.exe" "build\test_dual_stack.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_relay_pool.cpp  P5-D-5
cl %CXXFLAGS% tests\test_relay_pool.cpp /c /Fo:build\test_relay_pool.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_relay_pool.exe" "build\test_relay_pool.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_port_predictor.cpp  v3.6.0 P5-D-1 PortPredictor engine
cl %CXXFLAGS% tests\test_port_predictor.cpp /c /Fo:build\test_port_predictor.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_port_predictor.exe" "build\test_port_predictor.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_nat_stats.cpp  v3.6.0 P5-D-2 NatStats model
cl %CXXFLAGS% tests\test_nat_stats.cpp /c /Fo:build\test_nat_stats.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_nat_stats.exe" "build\test_nat_stats.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_nat_prediction_model.cpp  v3.6.0 P5-D-2 E2E prediction model
cl %CXXFLAGS% tests\test_nat_prediction_model.cpp /c /Fo:build\test_nat_prediction_model.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_nat_prediction_model.exe" "build\test_nat_prediction_model.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_cgn_dynamic_threshold.cpp  v3.6.1 P5-D-4 CGN dynamic threshold
cl %CXXFLAGS% tests\test_cgn_dynamic_threshold.cpp /c /Fo:build\test_cgn_dynamic_threshold.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_cgn_dynamic_threshold.exe" "build\test_cgn_dynamic_threshold.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_holepuncher_adaptive.cpp  v3.6.1 P5-D-4 Holepuncher adaptive candidates
cl %CXXFLAGS% tests\test_holepuncher_adaptive.cpp /c /Fo:build\test_holepuncher_adaptive.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_holepuncher_adaptive.exe" "build\test_holepuncher_adaptive.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_udp_probe.cpp  v4.4.0 P0-G1 UDP availability tri-state probe
cl %CXXFLAGS% tests\test_udp_probe.cpp /c /Fo:build\test_udp_probe.obj >build\err_cl_test_udp_probe.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_udp_probe.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_udp_probe.exe" "build\test_udp_probe.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_udp_probe.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_udp_probe.txt & exit /b 1 )

echo   tests\test_tcp_fallback.cpp  v4.4.0 P0-G2 TCP fallback orchestration
cl %CXXFLAGS% tests\test_tcp_fallback.cpp /c /Fo:build\test_tcp_fallback.obj >build\err_cl_test_tcp_fallback.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_tcp_fallback.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_tcp_fallback.exe" "build\test_tcp_fallback.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_tcp_fallback.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_tcp_fallback.txt & exit /b 1 )

echo   tests\test_passive_endpoint_update.cpp  v4.4.1 P0-G3 passive endpoint updater
cl %CXXFLAGS% tests\test_passive_endpoint_update.cpp /c /Fo:build\test_passive_endpoint_update.obj >build\err_cl_test_passive_endpoint_update.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_passive_endpoint_update.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_passive_endpoint_update.exe" "build\test_passive_endpoint_update.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_passive_endpoint_update.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_passive_endpoint_update.txt & exit /b 1 )

echo   tests\test_single_dest_holepunch.cpp  v4.4.1 P0-G4 single-dest symmetric NAT holepunch
cl %CXXFLAGS% tests\test_single_dest_holepunch.cpp /c /Fo:build\test_single_dest_holepunch.obj >build\err_cl_test_single_dest_holepunch.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_single_dest_holepunch.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_single_dest_holepunch.exe" "build\test_single_dest_holepunch.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_single_dest_holepunch.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_single_dest_holepunch.txt & exit /b 1 )

echo   tests\test_ice_optimizations.cpp  v4.4.1 P0-G5 ICE session optimizations
cl %CXXFLAGS% tests\test_ice_optimizations.cpp /c /Fo:build\test_ice_optimizations.obj >build\err_cl_test_ice_optimizations.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_ice_optimizations.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_ice_optimizations.exe" "build\test_ice_optimizations.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_ice_optimizations.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_ice_optimizations.txt & exit /b 1 )

echo   tests\test_server_config.cpp  v4.4.2 P2-G6 NAT server config remote pushdown
cl %CXXFLAGS% tests\test_server_config.cpp /c /Fo:build\test_server_config.obj >build\err_cl_test_server_config.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_server_config.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_server_config.exe" "build\test_server_config.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_server_config.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_server_config.txt & exit /b 1 )

echo   tests\test_hide_ip.cpp  v4.4.2 P2-G8 hide real IP privacy mode
cl %CXXFLAGS% tests\test_hide_ip.cpp /c /Fo:build\test_hide_ip.obj >build\err_cl_test_hide_ip.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_hide_ip.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_hide_ip.exe" "build\test_hide_ip.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_hide_ip.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_hide_ip.txt & exit /b 1 )

echo   tests\test_network_change.cpp  v4.4.2 P2-G7 network change rebuild state machine
cl %CXXFLAGS% tests\test_network_change.cpp /c /Fo:build\test_network_change.obj >build\err_cl_test_network_change.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_network_change.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_network_change.exe" "build\test_network_change.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" ws2_32.lib user32.lib iphlpapi.lib /SUBSYSTEM:CONSOLE >build\err_link_test_network_change.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_network_change.txt & exit /b 1 )

echo   tests\test_endpoint_last_attempt.cpp  v3.6.1 P5-D-4 Endpoint last attempt before relay
cl %CXXFLAGS% tests\test_endpoint_last_attempt.cpp /c /Fo:build\test_endpoint_last_attempt.obj >build\err_cl_test_endpoint_last_attempt.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_endpoint_last_attempt.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_endpoint_last_attempt.exe" "build\test_endpoint_last_attempt.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib iphlpapi.lib /SUBSYSTEM:CONSOLE >build\err_link_test_endpoint_last_attempt.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_endpoint_last_attempt.txt & exit /b 1 )

echo   tests\test_node_profile.cpp  v2.0 Phase 1 NodeProfile unit tests
cl %CXXFLAGS% tests\test_node_profile.cpp /c /Fo:build\test_node_profile.obj >build\err_cl_test_node_profile.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_node_profile.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_node_profile.exe" "build\test_node_profile.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_node_profile.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_node_profile.txt & exit /b 1 )

echo   tests\test_multipath_coordinated.cpp  v2.0 Phase 1 MultipathCoordinatedSelector unit tests
cl %CXXFLAGS% tests\test_multipath_coordinated.cpp /c /Fo:build\test_multipath_coordinated.obj >build\err_cl_test_multipath_coordinated.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_multipath_coordinated.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_multipath_coordinated.exe" "build\test_multipath_coordinated.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_multipath_coordinated.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_multipath_coordinated.txt & exit /b 1 )

echo   tests\test_control_plane.cpp  v2.0 Phase 1 lightweight control plane unit tests
cl %CXXFLAGS% tests\test_control_plane.cpp /c /Fo:build\test_control_plane.obj >build\err_cl_test_control_plane.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_control_plane.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_control_plane.exe" "build\test_control_plane.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_control_plane.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_control_plane.txt & exit /b 1 )

echo   tests\test_config_distributor.cpp  v2.1 Phase 2 config distributor unit tests
cl %CXXFLAGS% tests\test_config_distributor.cpp /c /Fo:build\test_config_distributor.obj >build\err_cl_test_config_distributor.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_config_distributor.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_config_distributor.exe" "build\test_config_distributor.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_config_distributor.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_config_distributor.txt & exit /b 1 )

echo   tests\test_config_propagation.cpp  v2.1 Phase 2 config propagation integration tests
cl %CXXFLAGS% tests\test_config_propagation.cpp /c /Fo:build\test_config_propagation.obj >build\err_cl_test_config_propagation.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_config_propagation.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_config_propagation.exe" "build\test_config_propagation.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_config_propagation.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_config_propagation.txt & exit /b 1 )

echo   tests\test_collective.cpp  v2.1 Phase 2 collective primitives (AllGather/Broadcast) unit tests
cl %CXXFLAGS% tests\test_collective.cpp /c /Fo:build\test_collective.obj >build\err_cl_test_collective.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_collective.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_collective.exe" "build\test_collective.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_collective.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_collective.txt & exit /b 1 )

echo   tests\test_collective_v2.cpp  v2.1 Phase 2 M2 collective primitives (ReduceScatter/AllToAll) unit tests
cl %CXXFLAGS% tests\test_collective_v2.cpp /c /Fo:build\test_collective_v2.obj >build\err_cl_test_collective_v2.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_collective_v2.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_collective_v2.exe" "build\test_collective_v2.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_collective_v2.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_collective_v2.txt & exit /b 1 )

echo   tests\test_comm_planner_v2.cpp  v2.1 Phase 2 M3/M4 topology-aware planning unit tests
cl %CXXFLAGS% tests\test_comm_planner_v2.cpp /c /Fo:build\test_comm_planner_v2.obj >build\err_cl_test_comm_planner_v2.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_comm_planner_v2.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_comm_planner_v2.exe" "build\test_comm_planner_v2.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_comm_planner_v2.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_comm_planner_v2.txt & exit /b 1 )

echo   tests\test_ring_engine.cpp  v2.2 Phase 3 P3-B Ring algorithm engine unit tests
cl %CXXFLAGS% tests\test_ring_engine.cpp /c /Fo:build\test_ring_engine.obj >build\err_cl_test_ring_engine.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_ring_engine.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_ring_engine.exe" "build\test_ring_engine.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_ring_engine.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_ring_engine.txt & exit /b 1 )

echo   tests\test_tree_engine.cpp  v2.2 Phase 3 P3-C Tree algorithm engine unit tests
cl %CXXFLAGS% tests\test_tree_engine.cpp /c /Fo:build\test_tree_engine.obj >build\err_cl_test_tree_engine.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_tree_engine.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_tree_engine.exe" "build\test_tree_engine.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_tree_engine.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_tree_engine.txt & exit /b 1 )

echo   tests\test_rh_engine.cpp  v2.2 Phase 3 P3-D RecursiveHalving algorithm engine unit tests
cl %CXXFLAGS% tests\test_rh_engine.cpp /c /Fo:build\test_rh_engine.obj >build\err_cl_test_rh_engine.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_rh_engine.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_rh_engine.exe" "build\test_rh_engine.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_rh_engine.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_rh_engine.txt & exit /b 1 )

echo   tests\test_pe_engine.cpp  v2.2 Phase 3 P3-E PairwiseExchange algorithm engine unit tests
cl %CXXFLAGS% tests\test_pe_engine.cpp /c /Fo:build\test_pe_engine.obj >build\err_cl_test_pe_engine.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_pe_engine.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_pe_engine.exe" "build\test_pe_engine.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_pe_engine.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_pe_engine.txt & exit /b 1 )

echo   tests\test_collective_v3.cpp  v2.2 Phase 3 P3-F SyncPrimitives scheduling layer unit tests
cl %CXXFLAGS% tests\test_collective_v3.cpp /c /Fo:build\test_collective_v3.obj >build\err_cl_test_collective_v3.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_collective_v3.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_collective_v3.exe" "build\test_collective_v3.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_collective_v3.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_collective_v3.txt & exit /b 1 )

echo   tests\test_collective_v4.cpp  v2.2 Phase 3 P3-G large chunk sharding and reassembly unit tests
cl %CXXFLAGS% tests\test_collective_v4.cpp /c /Fo:build\test_collective_v4.obj >build\err_cl_test_collective_v4.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_collective_v4.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_collective_v4.exe" "build\test_collective_v4.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_collective_v4.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_collective_v4.txt & exit /b 1 )

echo   tests\test_sync_peers.cpp  v2.3 Phase 4 P4-B multi-EpChannel routing API unit tests
cl %CXXFLAGS% tests\test_sync_peers.cpp /c /Fo:build\test_sync_peers.obj >build\err_cl_test_sync_peers.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_sync_peers.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_sync_peers.exe" "build\test_sync_peers.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_sync_peers.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_sync_peers.txt & exit /b 1 )

echo   tests\test_ring_driver.cpp  v2.3 Phase 4 P4-C Ring driver guards and degradation unit tests
cl %CXXFLAGS% tests\test_ring_driver.cpp /c /Fo:build\test_ring_driver.obj >build\err_cl_test_ring_driver.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_ring_driver.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_ring_driver.exe" "build\test_ring_driver.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_ring_driver.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_ring_driver.txt & exit /b 1 )

echo   tests\test_algo_dispatch_ring.cpp  v2.3 Phase 4 P4-G algorithm dispatch unit tests
cl %CXXFLAGS% tests\test_algo_dispatch_ring.cpp /c /Fo:build\test_algo_dispatch_ring.obj >build\err_cl_test_algo_dispatch_ring.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_algo_dispatch_ring.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_algo_dispatch_ring.exe" "build\test_algo_dispatch_ring.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_algo_dispatch_ring.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_algo_dispatch_ring.txt & exit /b 1 )

echo   tests\test_tree_driver.cpp  v2.3 Phase 4 P4-D Tree driver guards and degradation unit tests
cl %CXXFLAGS% tests\test_tree_driver.cpp /c /Fo:build\test_tree_driver.obj >build\err_cl_test_tree_driver.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_tree_driver.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_tree_driver.exe" "build\test_tree_driver.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_tree_driver.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_tree_driver.txt & exit /b 1 )

echo   tests\test_algo_dispatch_tree.cpp  v2.3 Phase 4 P4-D Tree algorithm dispatch unit tests
cl %CXXFLAGS% tests\test_algo_dispatch_tree.cpp /c /Fo:build\test_algo_dispatch_tree.obj >build\err_cl_test_algo_dispatch_tree.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_algo_dispatch_tree.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_algo_dispatch_tree.exe" "build\test_algo_dispatch_tree.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_algo_dispatch_tree.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_algo_dispatch_tree.txt & exit /b 1 )

echo   tests\test_rh_driver.cpp  v2.3 Phase 4 P4-E RH driver guards and degradation unit tests
cl %CXXFLAGS% tests\test_rh_driver.cpp /c /Fo:build\test_rh_driver.obj >build\err_cl_test_rh_driver.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_rh_driver.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_rh_driver.exe" "build\test_rh_driver.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_rh_driver.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_rh_driver.txt & exit /b 1 )

echo   tests\test_algo_dispatch_rh.cpp  v2.3 Phase 4 P4-E RH algorithm dispatch unit tests
cl %CXXFLAGS% tests\test_algo_dispatch_rh.cpp /c /Fo:build\test_algo_dispatch_rh.obj >build\err_cl_test_algo_dispatch_rh.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_algo_dispatch_rh.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_algo_dispatch_rh.exe" "build\test_algo_dispatch_rh.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_algo_dispatch_rh.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_algo_dispatch_rh.txt & exit /b 1 )

echo   tests\test_pe_driver.cpp  v2.3 Phase 4 P4-F PE driver guards and degradation unit tests
cl %CXXFLAGS% tests\test_pe_driver.cpp /c /Fo:build\test_pe_driver.obj >build\err_cl_test_pe_driver.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_pe_driver.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_pe_driver.exe" "build\test_pe_driver.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_pe_driver.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_pe_driver.txt & exit /b 1 )

echo   tests\test_algo_dispatch_pe.cpp  v2.3 Phase 4 P4-F PE algorithm dispatch unit tests
cl %CXXFLAGS% tests\test_algo_dispatch_pe.cpp /c /Fo:build\test_algo_dispatch_pe.obj >build\err_cl_test_algo_dispatch_pe.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_algo_dispatch_pe.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_algo_dispatch_pe.exe" "build\test_algo_dispatch_pe.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_algo_dispatch_pe.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_algo_dispatch_pe.txt & exit /b 1 )

echo   tests\test_phase4_e2e.cpp  v2.3 Phase 4 P4-H end-to-end integration tests
cl %CXXFLAGS% tests\test_phase4_e2e.cpp /c /Fo:build\test_phase4_e2e.obj >build\err_cl_test_phase4_e2e.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_phase4_e2e.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_phase4_e2e.exe" "build\test_phase4_e2e.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_phase4_e2e.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_phase4_e2e.txt & exit /b 1 )

echo   tests\test_cross_domain_control.cpp  v3.0 V3-A cross-domain control plane unit tests
cl %CXXFLAGS% tests\test_cross_domain_control.cpp /c /Fo:build\test_cross_domain_control.obj >build\err_cl_test_cross_domain_control.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_cross_domain_control.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_cross_domain_control.exe" "build\test_cross_domain_control.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_cross_domain_control.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_cross_domain_control.txt & exit /b 1 )

echo   tests\test_cross_domain_data_plane.cpp  v3.1 V3-B cross-domain data plane unit tests
cl %CXXFLAGS% tests\test_cross_domain_data_plane.cpp /c /Fo:build\test_cross_domain_data_plane.obj >build\err_cl_test_cross_domain_data_plane.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_cross_domain_data_plane.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_cross_domain_data_plane.exe" "build\test_cross_domain_data_plane.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >build\err_link_test_cross_domain_data_plane.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_cross_domain_data_plane.txt & exit /b 1 )

echo   tests\test_endpoint_set_user_data.cpp  P5-C-1
cl %CXXFLAGS% tests\test_endpoint_set_user_data.cpp /c /Fo:build\test_endpoint_set_user_data.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_endpoint_set_user_data.exe" "build\test_endpoint_set_user_data.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul

echo ============================================================================
echo  v3.1.4 hotfix tests (A9 Stream FIN-only half-close)
echo ============================================================================

echo   tests\test_stream_fin_half_close.cpp  v3.1.4 A9 Stream FIN-only half-close
cl %CXXFLAGS% tests\test_stream_fin_half_close.cpp /c /Fo:build\test_stream_fin_half_close.obj >build\err_cl_test_stream_fin_half_close.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_stream_fin_half_close.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_stream_fin_half_close.exe" "build\test_stream_fin_half_close.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_stream_fin_half_close.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_stream_fin_half_close.txt & exit /b 1 )

echo.
echo ============================================================================
echo  v1.5.0.1 hotfix tests (P0-1 retx + payload audit + periodic FC + IW10)
echo ============================================================================

echo   tests\test_retransmit_oos_recovery.cpp
cl %CXXFLAGS% tests\test_retransmit_oos_recovery.cpp /c /Fo:build\test_retransmit_oos_recovery.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_retransmit_oos_recovery.exe" "build\test_retransmit_oos_recovery.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_payload_audit.cpp
cl %CXXFLAGS% tests\test_payload_audit.cpp /c /Fo:build\test_payload_audit.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_payload_audit.exe" "build\test_payload_audit.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_periodic_fc_emission.cpp
cl %CXXFLAGS% tests\test_periodic_fc_emission.cpp /c /Fo:build\test_periodic_fc_emission.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_periodic_fc_emission.exe" "build\test_periodic_fc_emission.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo   tests\test_iw10.cpp
cl %CXXFLAGS% tests\test_iw10.cpp /c /Fo:build\test_iw10.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_iw10.exe" "build\test_iw10.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo.
echo ============================================================================
echo  v1.5.0.1 E2E stress test (Windows MSVC C client)
echo ============================================================================

echo   tests\test_e2e_stress_client.c
cl /TC /std:c11 /EHsc /permissive- /O2 /utf-8 /MD /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include tests\test_e2e_stress_client.c /c /Fo:build\test_e2e_stress_client.obj >nul
if errorlevel 1 ( echo FAILED & exit /b 1 )
link /NOLOGO /OUT:"build\test_e2e_stress_client.exe" "build\test_e2e_stress_client.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib bcrypt.lib /SUBSYSTEM:CONSOLE >nul

echo.
echo ============================================================================
echo  v3.7.0 Reliability: chunk_hash + atomic_write unit tests
echo ============================================================================

echo   tests\test_chunk_hash.cpp  v3.7.0 sha256 chunk verify + Merkle Root
cl %CXXFLAGS% tests\test_chunk_hash.cpp /c /Fo:build\test_chunk_hash.obj >build\err_cl_test_chunk_hash.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_chunk_hash.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_chunk_hash.exe" "build\test_chunk_hash.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_chunk_hash.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_chunk_hash.txt & exit /b 1 )

echo   tests\test_atomic_write.cpp  v3.7.0 temp dir + atomic rename
cl %CXXFLAGS% tests\test_atomic_write.cpp /c /Fo:build\test_atomic_write.obj >build\err_cl_test_atomic_write.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_atomic_write.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_atomic_write.exe" "build\test_atomic_write.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_atomic_write.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_atomic_write.txt & exit /b 1 )

echo ============================================================================
echo  v4.5.0 endpoint_id key file persistence unit tests
echo ============================================================================

echo   tests\test_key_file_persistence.cpp  v4.5.0 42B container + legacy compat + CRC32
cl %CXXFLAGS% tests\test_key_file_persistence.cpp /c /Fo:build\test_key_file_persistence.obj >build\err_cl_test_key_file_persistence.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_key_file_persistence.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_key_file_persistence.exe" "build\test_key_file_persistence.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib advapi32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_key_file_persistence.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_key_file_persistence.txt & exit /b 1 )

echo   tests\e2e_endpoint_id_test.cpp  v4.5.0 endpoint_id persistence e2e (3 components)
cl %CXXFLAGS% tests\e2e_endpoint_id_test.cpp /c /Fo:build\e2e_endpoint_id_test.obj >build\err_cl_e2e_endpoint_id_test.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_e2e_endpoint_id_test.txt & exit /b 1 )
link /NOLOGO /OUT:"build\e2e_endpoint_id_test.exe" "build\e2e_endpoint_id_test.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib advapi32.lib /SUBSYSTEM:CONSOLE >build\err_link_e2e_endpoint_id_test.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_e2e_endpoint_id_test.txt & exit /b 1 )

echo ============================================================================
echo  v3.7.1 Reliability: ModelManifest content-addressing unit tests
echo ============================================================================

echo   tests\test_model_manifest.cpp  v3.7.1 Collection manifest + sha256 + atomic
cl %CXXFLAGS% tests\test_model_manifest.cpp /c /Fo:build\test_model_manifest.obj >build\err_cl_test_model_manifest.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_model_manifest.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_model_manifest.exe" "build\test_model_manifest.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_model_manifest.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_model_manifest.txt & exit /b 1 )

echo ============================================================================
echo  v3.7.3 Reliability: ParallelDownloader unit tests
echo ============================================================================

echo   tests\test_parallel_downloader.cpp  v3.7.3 thread pool + retry + concurrency
cl %CXXFLAGS% tests\test_parallel_downloader.cpp /c /Fo:build\test_parallel_downloader.obj >build\err_cl_test_parallel_downloader.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_parallel_downloader.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_parallel_downloader.exe" "build\test_parallel_downloader.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_parallel_downloader.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_parallel_downloader.txt & exit /b 1 )

echo ============================================================================
echo  v3.7.4 Reliability: ShardStateStore unit tests
echo ============================================================================

echo   tests\test_shard_state_store.cpp  v3.7.4 resume state + atomic save/load
cl %CXXFLAGS% tests\test_shard_state_store.cpp /c /Fo:build\test_shard_state_store.obj >build\err_cl_test_shard_state_store.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_shard_state_store.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_shard_state_store.exe" "build\test_shard_state_store.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_shard_state_store.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_shard_state_store.txt & exit /b 1 )

echo ============================================================================
echo  v3.8.0 Security: PeerErrorTracker unit tests
echo ============================================================================

echo   tests\test_peer_error_tracker.cpp  v3.8.0 per-peer error count + auto degrade
cl %CXXFLAGS% tests\test_peer_error_tracker.cpp /c /Fo:build\test_peer_error_tracker.obj >build\err_cl_test_peer_error_tracker.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_peer_error_tracker.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_peer_error_tracker.exe" "build\test_peer_error_tracker.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_peer_error_tracker.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_peer_error_tracker.txt & exit /b 1 )

echo ============================================================================
echo  v3.8.4 Security: MerkleTree unit tests
echo ============================================================================

echo   tests\test_merkle_tree.cpp  v3.8.4 TensorStream Merkle Root integrity
cl %CXXFLAGS% tests\test_merkle_tree.cpp /c /Fo:build\test_merkle_tree.obj >build\err_cl_test_merkle_tree.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_merkle_tree.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_merkle_tree.exe" "build\test_merkle_tree.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_merkle_tree.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_merkle_tree.txt & exit /b 1 )

echo ============================================================================
echo  v3.8.5 Security: SignedMessage unit tests
echo ============================================================================

echo   tests\test_signed_message.cpp  v3.8.5 Ed25519 signed envelope
cl %CXXFLAGS% tests\test_signed_message.cpp /c /Fo:build\test_signed_message.obj >build\err_cl_test_signed_message.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_signed_message.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_signed_message.exe" "build\test_signed_message.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_signed_message.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_signed_message.txt & exit /b 1 )

echo ============================================================================
echo  v3.8.6 Security: ReplayProtection unit tests
echo ============================================================================

echo   tests\test_replay_protection.cpp  v3.8.6 nonce + timestamp replay protection
cl %CXXFLAGS% tests\test_replay_protection.cpp /c /Fo:build\test_replay_protection.obj >build\err_cl_test_replay_protection.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_replay_protection.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_replay_protection.exe" "build\test_replay_protection.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_replay_protection.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_replay_protection.txt & exit /b 1 )

echo ============================================================================
echo  v3.9.5 M5: Role-based ALPN subset unit tests
echo ============================================================================

echo   tests\test_role_alpn.cpp  v3.9.5 NodeRole + role_default_alpns + is_role_authorized
cl %CXXFLAGS% tests\test_role_alpn.cpp /c /Fo:build\test_role_alpn.obj >build\err_cl_test_role_alpn.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_role_alpn.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_role_alpn.exe" "build\test_role_alpn.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_role_alpn.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_role_alpn.txt & exit /b 1 )

echo ============================================================================
echo  v3.9.6 M17: Per-chunk sha256 incremental verification
echo ============================================================================

echo   tests\test_chunk_verify_stream.cpp  v3.9.6 ShardHashAnnounce + chunk verify
cl %CXXFLAGS% tests\test_chunk_verify_stream.cpp /c /Fo:build\test_chunk_verify_stream.obj >build\err_cl_test_chunk_verify_stream.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_chunk_verify_stream.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_chunk_verify_stream.exe" "build\test_chunk_verify_stream.obj" "build\linoh.lib" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_chunk_verify_stream.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_chunk_verify_stream.txt & exit /b 1 )

echo ============================================================================
echo  v3.9.0 Transport: QUIC config + BBR v2 pacing unit tests
echo ============================================================================

echo   tests\test_transport_config.cpp  v3.9.0 PacingLimiter + BBR pacing integration
cl %CXXFLAGS% tests\test_transport_config.cpp /c /Fo:build\test_transport_config.obj >build\err_cl_test_transport_config.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_transport_config.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_transport_config.exe" "build\test_transport_config.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_transport_config.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_transport_config.txt & exit /b 1 )

echo ============================================================================
echo  v3.9.2 Transport: TensorPipeline async serialization unit tests
echo ============================================================================

echo   tests\test_tensor_pipeline.cpp  v3.9.2 async serialization pipeline
cl %CXXFLAGS% tests\test_tensor_pipeline.cpp /c /Fo:build\test_tensor_pipeline.obj >build\err_cl_test_tensor_pipeline.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_tensor_pipeline.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_tensor_pipeline.exe" "build\test_tensor_pipeline.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_tensor_pipeline.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_tensor_pipeline.txt & exit /b 1 )

echo ============================================================================
echo  v3.9.3 Transport: ConcurrentForwarder parallel forwarding unit tests
echo ============================================================================

echo   tests\test_concurrent_forwarder.cpp  v3.9.3 parallel forwarding
cl %CXXFLAGS% tests\test_concurrent_forwarder.cpp /c /Fo:build\test_concurrent_forwarder.obj >build\err_cl_test_concurrent_forwarder.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_concurrent_forwarder.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_concurrent_forwarder.exe" "build\test_concurrent_forwarder.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_concurrent_forwarder.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_concurrent_forwarder.txt & exit /b 1 )

echo ============================================================================
echo  v3.9.1 Transport: ConnectionMonitor bandwidth feedback loop unit tests
echo ============================================================================

echo   tests\test_connection_monitor.cpp  v3.9.1 bandwidth feedback
cl %CXXFLAGS% tests\test_connection_monitor.cpp /c /Fo:build\test_connection_monitor.obj >build\err_cl_test_connection_monitor.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_connection_monitor.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_connection_monitor.exe" "build\test_connection_monitor.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_connection_monitor.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_connection_monitor.txt & exit /b 1 )

echo.
echo ============================================================================
echo  v3.9.4 Transport: bf16 hidden_state transparent transport unit tests
echo ============================================================================
echo   tests\test_bf16_transport.cpp  v3.9.4 bf16 transparent transport
cl %CXXFLAGS% tests\test_bf16_transport.cpp /c /Fo:build\test_bf16_transport.obj >build\err_cl_test_bf16_transport.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_test_bf16_transport.txt & exit /b 1 )
link /NOLOGO /OUT:"build\test_bf16_transport.exe" "build\test_bf16_transport.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_test_bf16_transport.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_test_bf16_transport.txt & exit /b 1 )

echo.
echo ============================================================================
echo  v4.3.0 M21 E2E: end-to-end integration tests (PP chain + multimodal)
echo ============================================================================
set "E2EFLAGS=%CXXFLAGS% /Itests"
echo   tests\e2e\e2e_pp_chain.cpp  v4.3.0 PP chain LLM hidden_state e2e
cl %E2EFLAGS% tests\e2e\e2e_pp_chain.cpp /c /Fo:build\e2e_pp_chain.obj >build\err_cl_e2e_pp_chain.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_e2e_pp_chain.txt & exit /b 1 )
link /NOLOGO /OUT:"build\e2e_pp_chain.exe" "build\e2e_pp_chain.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_e2e_pp_chain.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_e2e_pp_chain.txt & exit /b 1 )

echo   tests\e2e\e2e_multimodal.cpp  v4.3.0 multimodal channels e2e (img+video+audio)
cl %E2EFLAGS% tests\e2e\e2e_multimodal.cpp /c /Fo:build\e2e_multimodal.obj >build\err_cl_e2e_multimodal.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_e2e_multimodal.txt & exit /b 1 )
link /NOLOGO /OUT:"build\e2e_multimodal.exe" "build\e2e_multimodal.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_e2e_multimodal.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_e2e_multimodal.txt & exit /b 1 )

echo   tests\e2e\e2e_event_loop.cpp  v4.3.0 event loop driven e2e
cl %E2EFLAGS% tests\e2e\e2e_event_loop.cpp /c /Fo:build\e2e_event_loop.obj >build\err_cl_e2e_event_loop.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_e2e_event_loop.txt & exit /b 1 )
link /NOLOGO /OUT:"build\e2e_event_loop.exe" "build\e2e_event_loop.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_e2e_event_loop.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_e2e_event_loop.txt & exit /b 1 )

echo   tests\e2e\e2e_progress.cpp  v4.3.0 double-layer progress report e2e
cl %E2EFLAGS% tests\e2e\e2e_progress.cpp /c /Fo:build\e2e_progress.obj >build\err_cl_e2e_progress.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_cl_e2e_progress.txt & exit /b 1 )
link /NOLOGO /OUT:"build\e2e_progress.exe" "build\e2e_progress.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >build\err_link_e2e_progress.txt 2>&1
if errorlevel 1 ( echo FAILED & type build\err_link_e2e_progress.txt & exit /b 1 )

echo.
echo ============================================================================
echo  Build Summary
echo ============================================================================
dir /b "build\*.exe" 2>nul
echo.
echo Build completed successfully.
endlocal


