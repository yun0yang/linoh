@echo off
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

set "CXXFLAGS=/std:c++20 /EHsc /permissive- /O2 /utf-8 /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include"

echo Compiling test_crypto_vectors.cpp...
cl %CXXFLAGS% tests\test_crypto_vectors.cpp /c /Fo:build\test_crypto_vectors.obj >nul 2>&1
if errorlevel 1 (
    echo COMPILE FAILED
    cl %CXXFLAGS% tests\test_crypto_vectors.cpp /c /Fo:build\test_crypto_vectors.obj
    exit /b 1
)

echo Linking...
link /NOLOGO /OUT:"build\test_crypto_vectors.exe" "build\test_crypto_vectors.obj" "build\linoh.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE >nul 2>&1
if errorlevel 1 (
    echo LINK FAILED
    link /NOLOGO /OUT:"build\test_crypto_vectors.exe" "build\test_crypto_vectors.obj" "build\linoh.lib" ws2_32.lib user32.lib /SUBSYSTEM:CONSOLE
    exit /b 1
)

echo Running...
build\test_crypto_vectors.exe
endlocal
