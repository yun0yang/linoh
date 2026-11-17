@echo off
REM ============================================================================
REM  linoh.lib only build (skips examples/tests for faster PoC iteration)
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

set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include"

echo ============================================================================
echo  Building linoh.lib (lib only, no examples/tests)
echo ============================================================================

set "OBJS="
for %%F in (
  src\endpoint\builder.cpp
  src\endpoint\connection.cpp
  src\endpoint\endpoint.cpp
  src\net\socket.cpp
  src\net\udp_transport.cpp
  src\protocol\packet.cpp
  src\protocol\router.cpp
  src\protocol\ack.cpp
  src\protocol\loss_recovery.cpp
  src\protocol\flow_control.cpp
  src\protocol\path_migration.cpp
  src\tls\crypto_provider.cpp
  src\tls\ed25519_core.cpp
  src\tls\ed25519_verifier.cpp
  src\tls\handshake_token_key.cpp
  src\crypto\x25519.cpp
  src\crypto\hkdf.cpp
  src\base\key.cpp
  src\base\endpoint_addr.cpp
  src\util\crypto.cpp
  src\address_lookup\pkarr_publisher.cpp
  src\address_lookup\pkarr_server.cpp
  src\relay\client.cpp
  src\relay\server.cpp
  src\relay\tls_channel.cpp
  src\linoh_c.cpp
  third_party\openssl\src\evp_stub.cpp
) do (
  echo   compile %%F
  cl %CXXFLAGS% %%F /c /Fo:build\%%~nF.obj >build\err_%%~nF.txt 2>&1
  if errorlevel 1 (
    echo FAILED: %%F
    type build\err_%%~nF.txt
    exit /b 1
  )
  set "OBJS=!OBJS! build\%%~nF.obj"
)

echo   link linoh.lib
lib /NOLOGO /OUT:"build\linoh.lib" %OBJS%

echo.
dir "build\linoh.lib"
echo Build completed successfully.
endlocal
