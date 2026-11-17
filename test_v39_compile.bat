@echo off
REM ============================================================================
REM  v3.9.x standalone compile verification
REM  v3.9.0: pacing_limiter (header-only) + BBR v2 pacing integration
REM          Endpoint Config QUIC transport params
REM  pacing_limiter.hpp is header-only, included by bbr_v2.cpp.
REM  bbr_v2.cpp is recompiled here (new PacingLimiter) and linked as a direct
REM  obj — link.exe prefers direct obj symbols over linoh.lib's bbr_v2.obj,
REM  so no full lib rebuild needed.
REM  Requires: build\linoh.lib + build\linoh-base.lib (loss_recovery + other deps)
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

call "%VCVARSALL%" x64 >nul 2>&1
cd /d %~dp0
if not exist build mkdir build

set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include"

echo ============================================================================
echo  Step 1: Compile bbr_v2.cpp (new PacingLimiter integration)
echo ============================================================================
cl %CXXFLAGS% src\protocol\bbr_v2.cpp /c /Fo:build\v390_bbr_v2.obj
if errorlevel 1 ( echo FAILED bbr_v2 compile & exit /b 1 )

echo ============================================================================
echo  Step 2: Compile test_transport_config.cpp
echo ============================================================================
cl %CXXFLAGS% tests\test_transport_config.cpp /c /Fo:build\test_transport_config.obj
if errorlevel 1 ( echo FAILED test_transport_config compile & exit /b 1 )

echo ============================================================================
echo  Step 3: Link (v390_bbr_v2.obj takes priority over linoh.lib bbr_v2.obj)
echo ============================================================================
link /NOLOGO /OUT:"build\test_transport_config.exe" "build\v390_bbr_v2.obj" "build\test_transport_config.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_transport_config link & exit /b 1 )

echo ============================================================================
echo  Step 4: Run v3.9.0 test
echo ============================================================================
echo   running test_transport_config.exe
build\test_transport_config.exe
if errorlevel 1 ( echo FAILED test_transport_config run & exit /b 1 )

echo ============================================================================
echo  All v3.9.x tests passed
echo ============================================================================
endlocal
