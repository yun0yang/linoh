@echo off
setlocal enabledelayedexpansion

set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

set "VCVARSALL="
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"
    if defined VSINSTALL set "VCVARSALL=!VSINSTALL!\VC\Auxiliary\Build\vcvarsall.bat"
)
if not exist "%VCVARSALL%" (
    for %%E in (Community Professional Enterprise BuildTools) do (
        if not exist "%VCVARSALL%" if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARSALL=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat"
    )
)
if not exist "%VCVARSALL%" (
    echo ERROR: Could not find vcvarsall.bat
    exit /b 1
)
call "%VCVARSALL%" x64
if errorlevel 1 ( echo ERROR: vcvarsall failed & exit /b 1 )

cd /d %~dp0

set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include"

echo === compile src\relay\server.cpp ===
cl %CXXFLAGS% src\relay\server.cpp /c /Fo:build\relay_server.obj
if errorlevel 1 ( echo FAILED: server.cpp & exit /b 1 )

echo === link linoh-relay.lib ===
lib /NOLOGO /OUT:"build\linoh-relay.lib" build\relay_client.obj build\relay_server.obj build\relay_tls_channel.obj build\relay_access_control.obj
if errorlevel 1 ( echo FAILED: linoh-relay.lib & exit /b 1 )

echo === link test_relay_server.exe ===
link /NOLOGO /OUT:"build\test_relay_server.exe" "build\test_relay_server.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib bcrypt.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED: test_relay_server.exe & exit /b 1 )

echo === link test_relay_server_builder.exe ===
link /NOLOGO /OUT:"build\test_relay_server_builder.exe" "build\test_relay_server_builder.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" msvcrt.lib msvcprt.lib vcruntime.lib ucrt.lib ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED: test_relay_server_builder.exe & exit /b 1 )

echo === INCR BUILD OK ===
