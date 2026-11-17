@echo off
REM ============================================================================
REM  v3.7 单独编译验证脚本（chunk_hash + atomic_write + model_manifest）
REM  依赖：build\linoh-base.lib 已存在（含 chunk_hash + atomic_write + SHA256）
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
echo  Step 1: Compile v3.7.1/v3.7.3/v3.7.4 source files (not in linoh-base.lib yet)
echo ============================================================================
cl %CXXFLAGS% src\collection\model_manifest.cpp /c /Fo:build\v37_model_manifest.obj
if errorlevel 1 ( echo FAILED model_manifest compile & exit /b 1 )

cl %CXXFLAGS% src\collection\parallel_downloader.cpp /c /Fo:build\v37_parallel_downloader.obj
if errorlevel 1 ( echo FAILED parallel_downloader compile & exit /b 1 )

cl %CXXFLAGS% src\collection\shard_state_store.cpp /c /Fo:build\v37_shard_state_store.obj
if errorlevel 1 ( echo FAILED shard_state_store compile & exit /b 1 )

echo ============================================================================
echo  Step 2: Compile and link v3.7.0 tests (chunk_hash + atomic_write)
echo ============================================================================

echo   test_chunk_hash.cpp
cl %CXXFLAGS% tests\test_chunk_hash.cpp /c /Fo:build\test_chunk_hash.obj
if errorlevel 1 ( echo FAILED test_chunk_hash compile & exit /b 1 )
link /NOLOGO /OUT:"build\test_chunk_hash.exe" "build\test_chunk_hash.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_chunk_hash link & exit /b 1 )

echo   test_atomic_write.cpp
cl %CXXFLAGS% tests\test_atomic_write.cpp /c /Fo:build\test_atomic_write.obj
if errorlevel 1 ( echo FAILED test_atomic_write compile & exit /b 1 )
link /NOLOGO /OUT:"build\test_atomic_write.exe" "build\test_atomic_write.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_atomic_write link & exit /b 1 )

echo ============================================================================
echo  Step 3: Compile and link v3.7.1 test (model_manifest)
echo ============================================================================

echo   test_model_manifest.cpp
cl %CXXFLAGS% tests\test_model_manifest.cpp /c /Fo:build\test_model_manifest.obj
if errorlevel 1 ( echo FAILED test_model_manifest compile & exit /b 1 )
link /NOLOGO /OUT:"build\test_model_manifest.exe" "build\test_model_manifest.obj" "build\v37_model_manifest.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_model_manifest link & exit /b 1 )

echo ============================================================================
echo  Step 3b: Compile and link v3.7.3 test (parallel_downloader)
echo ============================================================================

echo   test_parallel_downloader.cpp
cl %CXXFLAGS% tests\test_parallel_downloader.cpp /c /Fo:build\test_parallel_downloader.obj
if errorlevel 1 ( echo FAILED test_parallel_downloader compile & exit /b 1 )
link /NOLOGO /OUT:"build\test_parallel_downloader.exe" "build\test_parallel_downloader.obj" "build\v37_parallel_downloader.obj" "build\v37_model_manifest.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_parallel_downloader link & exit /b 1 )

echo ============================================================================
echo  Step 3c: Compile and link v3.7.4 test (shard_state_store)
echo ============================================================================

echo   test_shard_state_store.cpp
cl %CXXFLAGS% tests\test_shard_state_store.cpp /c /Fo:build\test_shard_state_store.obj
if errorlevel 1 ( echo FAILED test_shard_state_store compile & exit /b 1 )
link /NOLOGO /OUT:"build\test_shard_state_store.exe" "build\test_shard_state_store.obj" "build\v37_shard_state_store.obj" "build\v37_model_manifest.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_shard_state_store link & exit /b 1 )

echo ============================================================================
echo  Step 4: Run v3.7 tests
echo ============================================================================

echo   running test_chunk_hash.exe
build\test_chunk_hash.exe
if errorlevel 1 ( echo FAILED test_chunk_hash run & exit /b 1 )

echo   running test_atomic_write.exe
build\test_atomic_write.exe
if errorlevel 1 ( echo FAILED test_atomic_write run & exit /b 1 )

echo   running test_model_manifest.exe
build\test_model_manifest.exe
if errorlevel 1 ( echo FAILED test_model_manifest run & exit /b 1 )

echo   running test_parallel_downloader.exe
build\test_parallel_downloader.exe
if errorlevel 1 ( echo FAILED test_parallel_downloader run & exit /b 1 )

echo   running test_shard_state_store.exe
build\test_shard_state_store.exe
if errorlevel 1 ( echo FAILED test_shard_state_store run & exit /b 1 )

echo ============================================================================
echo  All v3.7 tests passed
echo ============================================================================
endlocal
