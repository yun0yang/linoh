@echo off
REM Build linoh_relay_bridge.exe (Windows)
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
    echo ERROR: Could not find vcvarsall.bat
    exit /b 1
)

call "%VCVARSALL%" x64
cd /d %~dp0
if not exist build mkdir build

set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include"

echo Building tools\linoh_relay_bridge.cpp
cl %CXXFLAGS% tools\linoh_relay_bridge.cpp /c /Fo:build\linoh_relay_bridge.obj >build\err_relay_bridge.txt 2>&1
if errorlevel 1 (
    echo FAILED
    type build\err_relay_bridge.txt
    exit /b 1
)

link /NOLOGO /OUT:"build\linoh_relay_bridge.exe" "build\linoh_relay_bridge.obj" "build\linoh-base.lib" "build\linoh.lib" ws2_32.lib user32.lib advapi32.lib /SUBSYSTEM:CONSOLE >build\err_relay_bridge_link.txt 2>&1
if errorlevel 1 (
    echo LINK FAILED
    type build\err_relay_bridge_link.txt
    exit /b 1
)

echo SUCCESS: build\linoh_relay_bridge.exe
