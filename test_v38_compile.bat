@echo off
REM ============================================================================
REM  v3.8.x standalone compile verification
REM  v3.8.0: peer_error_tracker + biased select!
REM  v3.8.4: merkle_tree (TensorStream Merkle Root integrity)
REM  v3.8.5: signed_message (Ed25519 signed envelope)
REM  v3.8.6: replay_protection (nonce + timestamp replay protection)
REM  Requires: build\linoh-base.lib (base EndpointId PublicKey hash SHA256 chunk_hash)
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
echo  Step 1: Compile v3.8.0 source file (peer_error_tracker, not in lib yet)
echo ============================================================================
cl %CXXFLAGS% src\endpoint\peer_error_tracker.cpp /c /Fo:build\v38_peer_error_tracker.obj
if errorlevel 1 ( echo FAILED peer_error_tracker compile & exit /b 1 )

echo ============================================================================
echo  Step 2: Compile and link v3.8.0 test (test_peer_error_tracker)
echo ============================================================================

echo   test_peer_error_tracker.cpp
cl %CXXFLAGS% tests\test_peer_error_tracker.cpp /c /Fo:build\test_peer_error_tracker.obj
if errorlevel 1 ( echo FAILED test_peer_error_tracker compile & exit /b 1 )
link /NOLOGO /OUT:"build\test_peer_error_tracker.exe" "build\test_peer_error_tracker.obj" "build\v38_peer_error_tracker.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_peer_error_tracker link & exit /b 1 )

echo ============================================================================
echo  Step 3: Run v3.8.0 test
echo ============================================================================

echo   running test_peer_error_tracker.exe
build\test_peer_error_tracker.exe
if errorlevel 1 ( echo FAILED test_peer_error_tracker run & exit /b 1 )

echo ============================================================================
echo  Step 4: Compile v3.8.4 source file (merkle_tree, not in lib yet)
echo ============================================================================
cl %CXXFLAGS% src\crypto\merkle_tree.cpp /c /Fo:build\v384_merkle_tree.obj
if errorlevel 1 ( echo FAILED merkle_tree compile & exit /b 1 )

echo ============================================================================
echo  Step 5: Compile and link v3.8.4 test (test_merkle_tree)
echo ============================================================================

echo   test_merkle_tree.cpp
cl %CXXFLAGS% tests\test_merkle_tree.cpp /c /Fo:build\test_merkle_tree.obj
if errorlevel 1 ( echo FAILED test_merkle_tree compile & exit /b 1 )
link /NOLOGO /OUT:"build\test_merkle_tree.exe" "build\test_merkle_tree.obj" "build\v384_merkle_tree.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_merkle_tree link & exit /b 1 )

echo ============================================================================
echo  Step 6: Run v3.8.4 test
echo ============================================================================

echo   running test_merkle_tree.exe
build\test_merkle_tree.exe
if errorlevel 1 ( echo FAILED test_merkle_tree run & exit /b 1 )

echo ============================================================================
echo  Step 7: Compile v3.8.5 source file (signed_message, not in lib yet)
echo ============================================================================
cl %CXXFLAGS% src\crypto\signed_message.cpp /c /Fo:build\v385_signed_message.obj
if errorlevel 1 ( echo FAILED signed_message compile & exit /b 1 )

echo ============================================================================
echo  Step 8: Compile and link v3.8.5 test (test_signed_message)
echo ============================================================================

echo   test_signed_message.cpp
cl %CXXFLAGS% tests\test_signed_message.cpp /c /Fo:build\test_signed_message.obj
if errorlevel 1 ( echo FAILED test_signed_message compile & exit /b 1 )
link /NOLOGO /OUT:"build\test_signed_message.exe" "build\test_signed_message.obj" "build\v385_signed_message.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_signed_message link & exit /b 1 )

echo ============================================================================
echo  Step 9: Run v3.8.5 test
echo ============================================================================

echo   running test_signed_message.exe
build\test_signed_message.exe
if errorlevel 1 ( echo FAILED test_signed_message run & exit /b 1 )

echo ============================================================================
echo  Step 10: Compile v3.8.6 source file (replay_protection, not in lib yet)
echo ============================================================================
cl %CXXFLAGS% src\protocol\replay_protection.cpp /c /Fo:build\v386_replay_protection.obj
if errorlevel 1 ( echo FAILED replay_protection compile & exit /b 1 )

echo ============================================================================
echo  Step 11: Compile and link v3.8.6 test (test_replay_protection)
echo ============================================================================

echo   test_replay_protection.cpp
cl %CXXFLAGS% tests\test_replay_protection.cpp /c /Fo:build\test_replay_protection.obj
if errorlevel 1 ( echo FAILED test_replay_protection compile & exit /b 1 )
link /NOLOGO /OUT:"build\test_replay_protection.exe" "build\test_replay_protection.obj" "build\v386_replay_protection.obj" "build\linoh-base.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo FAILED test_replay_protection link & exit /b 1 )

echo ============================================================================
echo  Step 12: Run v3.8.6 test
echo ============================================================================

echo   running test_replay_protection.exe
build\test_replay_protection.exe
if errorlevel 1 ( echo FAILED test_replay_protection run & exit /b 1 )

echo ============================================================================
echo  All v3.8.x tests passed
echo ============================================================================
endlocal
