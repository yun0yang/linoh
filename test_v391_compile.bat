@echo off
REM ============================================================================
REM  v3.9.1 ConnectionMonitor independent compile + test script
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

set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include /Ithird_party\zstd"

echo ============================================================================
echo  Step 1: Compile connection_monitor.cpp (new v3.9.1 source)
echo ============================================================================
cl %CXXFLAGS% src\endpoint\connection_monitor.cpp /c /Fo:build\v391_connection_monitor.obj
if errorlevel 1 ( echo FAILED connection_monitor compile & exit /b 1 )

echo ============================================================================
echo  Step 2: Compile test_connection_monitor.cpp
echo ============================================================================
cl %CXXFLAGS% tests\test_connection_monitor.cpp /c /Fo:build\test_connection_monitor.obj
if errorlevel 1 ( echo FAILED test_connection_monitor compile & exit /b 1 )

echo ============================================================================
echo  Step 3: Link
echo ============================================================================
link /NOLOGO /OUT:"build\test_connection_monitor.exe" "build\test_connection_monitor.obj" "build\v391_connection_monitor.obj" "build\linoh.lib" "build\linoh-base.lib" "build\linoh-relay.lib" "build\linoh-dns-server.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_connection_monitor link & exit /b 1 )

echo ============================================================================
echo  Step 4: Run v3.9.1 test
echo ============================================================================
echo   running test_connection_monitor.exe
build\test_connection_monitor.exe
if errorlevel 1 ( echo FAILED test_connection_monitor run & exit /b 1 )

echo ============================================================================
echo  v3.9.1 ConnectionMonitor: ALL TESTS PASSED
echo ============================================================================
exit /b 0
