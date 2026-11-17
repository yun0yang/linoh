@echo off
REM ============================================================================
REM  v3.9.3 ConcurrentForwarder independent compile + test script
REM  Compiles concurrent_forwarder.cpp + test_concurrent_forwarder.cpp, links, and runs
REM ============================================================================

setlocal enabledelayedexpansion

REM --- Find vcvarsall.bat ---
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

set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include /Ithird_party\zstd"

echo ============================================================================
echo  Step 1: Compile concurrent_forwarder.cpp (new v3.9.3 source)
echo ============================================================================
cl %CXXFLAGS% src\multimodal\concurrent_forwarder.cpp /c /Fo:build\v393_concurrent_forwarder.obj
if errorlevel 1 ( echo FAILED concurrent_forwarder compile & exit /b 1 )

echo ============================================================================
echo  Step 2: Compile test_concurrent_forwarder.cpp
echo ============================================================================
cl %CXXFLAGS% tests\test_concurrent_forwarder.cpp /c /Fo:build\test_concurrent_forwarder.obj
if errorlevel 1 ( echo FAILED test_concurrent_forwarder compile & exit /b 1 )

echo ============================================================================
echo  Step 3: Link (v393_concurrent_forwarder.obj + test_concurrent_forwarder.obj + libs)
echo ============================================================================
link /NOLOGO /OUT:"build\test_concurrent_forwarder.exe" "build\v393_concurrent_forwarder.obj" "build\test_concurrent_forwarder.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_concurrent_forwarder link & exit /b 1 )

echo ============================================================================
echo  Step 4: Run v3.9.3 test
echo ============================================================================
echo   running test_concurrent_forwarder.exe
build\test_concurrent_forwarder.exe
if errorlevel 1 ( echo FAILED test_concurrent_forwarder run & exit /b 1 )

echo ============================================================================
echo  v3.9.3 ConcurrentForwarder: ALL TESTS PASSED
echo ============================================================================
exit /b 0
